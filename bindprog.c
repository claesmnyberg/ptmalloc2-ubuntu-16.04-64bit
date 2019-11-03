/*
 * Bind program to a port on locahost just like inetd does,
 * it comes handy for CTF challenges.
 *
 *  Copyright (c) 2017 Claes M. Nyberg <cmn@fuzzpoint.com>
 *  All rights reserved, all wrongs reversed.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 *  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/* Local functions */
static int bindprog(uint16_t, char **, char **);


static struct options {
	int env:1; /* Do not zero out environment */
	int gdb:1; /* Spawn gdb for each PID (require root on ubuntu) */
	int all:1; /* Listen on all IP addresses, not just localhost */
#define BINDPROG_TERM_CMD "gnome-terminal --geometry 106x74+1204+546 -x"
} opts;

/*
 * Bind program to port on localhost for testing
 * port in host byte order.
 */
static int
bindprog(uint16_t port, char **argv, char **envp)
{
	struct sockaddr_in sin;
	unsigned int addrlen = sizeof(struct sockaddr_in);
	int sock = 0;
	int yes = 1;
	int csock;

	memset(&sin, 0x00, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	if (opts.all == 0)
		sin.sin_addr.s_addr = inet_addr("127.0.0.1");

	/* Create IPv4 socket */
	if ( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "** Error: Failed to create socket: %s\n", 
			strerror(errno));
		goto error;
	}

	/* Reuse address */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
			(void *)&yes, sizeof(yes)) < 0) {
		fprintf(stderr, "** Error: Failed to reuse address: %s\n", 
			strerror(errno));
		goto error;
	}

	/* Bind socket to address */ 
	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		fprintf(stderr, "** Error: Failed to bind: %s\n", 
			strerror(errno));
		goto error;
	}

	/* Listen with a queue of 1 connecting client */
	if (listen(sock, 1) < 0) {
		fprintf(stderr, "** Error: Failed to listen: %s\n", 
			strerror(errno));
		goto error;
	}

	/* Accept clients and spawn program */
	printf("[%d] Accepting clients for '%s' on %s:%u\n", getpid(), 
		argv[0], inet_ntoa(sin.sin_addr), port);
	while ( (csock = accept(sock, (struct sockaddr *)&sin, &addrlen)) >= 0) {
		pid_t pid;

		printf("%s:%u connected\n", inet_ntoa(sin.sin_addr), 
			ntohs(sin.sin_port));	

		/* Fork */
		pid = fork();

		if (pid < 0) {
			fprintf(stderr, "** Error: fork() failed: %s\n", 
				strerror(errno));
			close(csock);
			continue;
		} 	

		/* Child */
		if (pid == 0) {
			pid_t p;

			/* fork() again to avoid zombie */
			if ( (p = fork()) != 0) {

				/* Spawn gdb */
				if (opts.gdb) {
					char buf[2048];
					char *term;

					if ( (term = getenv("BINDPROG_TERM_CMD")) == NULL)
						term = BINDPROG_TERM_CMD;

					snprintf(buf, sizeof(buf), 
						"%s gdb -quiet %s %d", term, argv[0], p);

					printf("executing %s\n", buf);
					system(buf);

				}

				printf("attach %d\n", p); 
				exit(EXIT_SUCCESS);
			}

			/* Close server socket */
			close(sock);

			/* Set up IO */
			dup2(csock, STDIN_FILENO);
			dup2(csock, STDOUT_FILENO);
			dup2(csock, STDERR_FILENO);
			close(csock);

			/* Execve program */
			execve(argv[0], argv, envp);
	
			fprintf(stderr, "** Error: execve(%s) failed: %s\n", 
				argv[0], strerror(errno));
			exit(EXIT_FAILURE);
		}	


		/* Wait for first child to finish */
		waitpid(pid, NULL, 0);

		/* Close unused client socket */
		close(csock);
	}

	fprintf(stderr, "** Error: Failed to accept: %s\n", 
		strerror(errno)); 

	error:
		if (sock > 0)
			close(sock);
		return -1;
}


void
usage(char *pname)
{
	printf("Bind program to port on localhost <cmn@nybergit.se>\n");
	printf("Usage: %s [Option(s)] <port> <path> [<args> ...]\n", pname);
	printf("Options:\n");
	printf("  -a       - Listen on all IP addresses, not just localhost\n");
	printf("  -e       - Do not zero out environment before execve\n");
	printf("  -g       - Spawn gdb in a gnome-terminal for each new PID\n");
	printf("             Set environment variable BINDPROG_TERM_CMD\n");
	exit(EXIT_FAILURE);
}


int
main(int argc, char **argv, char **envp)
{
	int opt;

	memset(&opts, 0x00, sizeof(opts));
	while ( (opt = getopt(argc, argv, "+aeg")) != -1) {
		switch (opt) {
			case 'a':
				opts.all = 1;
				break;

			case 'e':
				opts.env = 1;
				break;

			case 'g':
				opts.gdb = 1;
				break;
		}
	}

	if ((argc-optind) < 2)
		usage(argv[0]);	

	if ((getuid() != 0) && (opts.gdb)) {
		fprintf(stderr, "[**] Warning: Some Linux distros, like Ubuntu require root to debug a process\n");
	}

	bindprog(atoi(argv[optind]), &argv[optind+1], opts.env ? envp : NULL);
}
