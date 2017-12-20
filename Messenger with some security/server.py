#!/usr/bin/python

import socket

c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

addr = (' ', 50000)

try:
	c.sendto('HELLO', addr)

except socket.gaierror:

	print "BYE"
