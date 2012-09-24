#!/usr/bin/python
# -*- coding: utf8 -*-

import sys
import time

import gevent
import gevent.server

def cooltime(): return time.strftime("%a, %H:%M:%S GMT", time.gmtime())

BUFSIZE = 16384
DBG = False
conns = set()
maxseen = 0

def handle(sock, addr):
	global DBG, maxseen
	if DBG: print ' | connection from', addr
	conns.add(addr)
	if len(conns) > maxseen:
		maxseen = len(conns)

	sent = False
	while True:
		d = sock.recv(BUFSIZE)
		if not d: break
		if DBG: print ' -> RECV', repr(d)
		if not sent:
			sock.sendall("HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\nS_KNOWN\r\n")
			sent = True
			break
		
	if DBG: print ' \\ connection closed', addr
	conns.remove(addr)
	sock.close()

def print_stats():
	while True:
		print cooltime(), ' -- {0} active connections, max: {1}'.format(len(conns), maxseen)
		gevent.sleep(2.0)

def main():
	print 'gevperf startup!'
	gevent.spawn(print_stats)
	server = gevent.server.StreamServer(('0.0.0.0', 61000), handle)
	server.serve_forever()

	return 0

if __name__ == '__main__':
	if len(sys.argv) > 1 and sys.argv[1] == 'debug': DBG = True
	try:
		sys.exit(main())
	except KeyboardInterrupt:
		print >>sys.stderr, 'KeyboardInterrupt: Exiting.'
		sys.exit(0)
	except SystemExit:
		pass

