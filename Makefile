#
# What: ptmalloc2-ubuntu-16.04.4-64bit Makefile
# Author: Claes M Nyberg
# When: Summer 2018
#

SHELL=/bin/sh
CC = gcc
CFLAGS=-m64

none: all

all:
	${CC} ${CFLAGS} -Wall -ggdb -o mallfest mallfest.c
	${CC} ${CFLAGS} -Wall -o bindprog bindprog.c
	${CC} ${CFLAGS} -ggdb -z execstack -o vuln_3.1 vuln_3.1.c
	${CC} ${CFLAGS} -ggdb -z execstack -fno-stack-protector -o vuln_3.2 vuln_3.2.c
	${CC} ${CFLAGS} -ggdb -z execstack -fno-stack-protector -o vuln_3.3 vuln_3.3.c
	${CC} ${CFLAGS} -ggdb -z execstack -fno-stack-protector -o vuln_3.6 vuln_3.6.c

clean:
	rm -f mallfest
	rm -f bindprog
	rm -f vuln_3.1
	rm -f vuln_3.2
	rm -f vuln_3.3
	rm -f vuln_3.6
