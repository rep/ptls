#!/usr/bin/python
# -*- coding: utf8 -*-

# pcat, based on pwrtls

# you can test it with a local server and client
# - pcat listen --sock 6666 --state state1
# starting the server prints its pub key
# - pcat connect --sock 127.0.0.1:6666 --state state2 --rpub <remote pub key>


import os
import sys
import traceback
import argparse
import logging
import fcntl

import gevent.server
import gevent.socket
import gevent.select
import pwrtls

logger = logging.getLogger('pcat')
BUFSIZE = 16*1024

def fdnonblock(fd):
	fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)

def forwardstdin(stdin, sock):
	fdnonblock(stdin.fileno())
	try:
		while True:
			gevent.select.select([stdin], [], [])
			data = stdin.read()
			if not data: break
			sock.send(data)
	except pwrtls.pwrtls_closed:
		pass
	except:
		print 'exc in forwardstdin'
		traceback.print_exc()

def forwardsock(sock, stdout):
	fdnonblock(stdout.fileno())
	try:
		while True:
			data = sock.read()
			if not data: break
			stdout.write(data)
	except pwrtls.pwrtls_closed: pass
	except KeyboardInterrupt: pass
	except:
		print 'exc in forwardsock'
		traceback.print_exc()

def main():
	parser = argparse.ArgumentParser(description='pwrcall nacl test.')

	parser.add_argument('action', help='connect/listen', choices=['connect', 'listen', 'c', 'l'])
	parser.add_argument('--state', dest='state', help='path to state file', default='pwr.state')
	parser.add_argument('--sock', dest='sock', help='where to connect / what to bind', required=True)
	parser.add_argument('--rpub', dest='rpub', help='remove public key for verification')

	args = parser.parse_args()

	state = pwrtls.state_file(args.state)

	if args.rpub:
		args.rpub = args.rpub.decode('hex')

	if args.action[0] == 'c':
		ip, port = args.sock.split(':', 1)
		port = int(port)

		socket = gevent.socket.create_connection((ip, port))
		socket = pwrtls.wrap_socket(socket, **state)
		socket.do_handshake()
		print 'remote longpub', socket.remote_longpub.encode('hex')
		socket.write('hello from client!\n')
		g1 = gevent.spawn(forwardstdin, sys.stdin, socket)
		forwardsock(socket, sys.stdout)
		print 'server gone'
		socket.close()

	elif args.action[0] == 'l':
		if ':' in args.sock: ip, port = args.sock.split(':', 1)
		else: ip, port = '0.0.0.0', args.sock
		port = int(port)

		lsocket = gevent.socket.socket()
		lsocket.setsockopt(gevent.socket.SOL_SOCKET, gevent.socket.SO_REUSEADDR, 1)
		lsocket.bind((ip, port))
		lsocket.listen(1)
		socket, addr = lsocket.accept()
		lsocket.close()
		print 'new client:', addr
		socket = pwrtls.wrap_socket(socket, server_side=True, **state)
		socket.do_handshake()
		print 'remote longpub', socket.remote_longpub.encode('hex')
		socket.write('hello from server\n')
		forwardsock(socket, sys.stdout)
		print 'client gone', addr
		socket.close()

	elif args.action[0] == 's':
		if ':' in args.sock: ip, port = args.sock.split(':', 1)
		else: ip, port = '0.0.0.0', args.sock
		port = int(port)

		def handle(sock, addr):
			print 'new client:', addr
			socket = pwrtls.wrap_socket(sock, server_side=True, **state)
			socket.do_handshake()
			print 'remote longpub', socket.remote_longpub.encode('hex')
			socket.write('hello from server\n')
			forwardsock(socket, sys.stdout)
			print 'client gone', addr
			socket.close()

		server = gevent.server.StreamServer((ip, port), handle)
		server.serve_forever()

	return 0

if __name__ == '__main__':
	logging.basicConfig()
	try:
		sys.exit(main())
	except KeyboardInterrupt:
		print >>sys.stderr, 'KeyboardInterrupt: Exiting.'
		sys.exit(0)
	except SystemExit:
		pass
	except:
		traceback.print_exc()
		sys.exit(1)
