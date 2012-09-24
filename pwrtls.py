#!/usr/bin/python
# -*- coding: utf8 -*-

# needs gevent (recent probably), pymongo (for bson), nacl (pynacl)
# - if you don't have "pip"
#   -> apt-get install python-pip
# - pip install gevent
# - pip install pymongo
# - git clone git://github.com/seanlynch/pynacl.git
# - cd pynacl
# - python setup.py install


import sys
import os
import struct
import random
import logging

import bson
import nacl

from gevent.socket import socket

logger = logging.getLogger('pwrtls')
BUFSIZE = 16 * 1024

# state_file is BSON encoded dict/hash
# with pub,priv keys for the keypair
# and nonce for securing the longtermkey encryption on new connections
# {'pub':'\x\x\x', 'priv':'\x\x\x', 'nonce':'\x\x\x'}
def load_state_file(path):
	if not os.path.exists(path): return False
	d = open(path, 'rb').read()
	if not bson.is_valid(d): return False
	return bson.BSON(d).decode()

def init_state(path):
	pub, priv = nacl.crypto_box_keypair()
	nonce = rand48()
	state = {
		'pubkey':_b(pub), 
		'privkey':_b(priv), 
		'nonce':nonce,
	}
	d = bson.BSON.encode(state)
	open(path, 'wb').write(d)
	return state

def state_file(fpath):
	state = load_state_file(fpath)
	if not state:
		logger.warning('invalid state file. generating new one...')
		state = init_state(fpath)
	return state


def _b(x): return bson.binary.Binary(x)

# message creation helpers
def rand48(): return random.randint(2**47, 2**48-1)

def lnonce(num): return 'pwrnonce' + struct.pack('QQ', num, rand48())

def snonce(num): return 'pwrnonceshortXXX' + struct.pack('Q', num)

class pwrtls_exception(Exception): pass
class pwrtls_closed(Exception): pass

# get args from enced bson dict
def from_bson(enced, *args):
	dec = bson.BSON(enced).decode()
	if len(args) == 1: return dec[args[0]]
	return (dec.get(i,None) for i in args)

class PTLS_Socket(object):

	def __init__(self, sock, pubkey=None, privkey=None, nonce=None):
		print 'PTLS_Socket init', repr(nonce)
		self._sock = socket(_sock=sock)

		self.pubkey = pubkey
		self.privkey = privkey
		self.nonce = nonce
		self.shortpub, self.shortpriv = nacl.crypto_box_keypair()
		self.rbuf = ''

	def _recv_frame(self):
		lengthbytes = self._recv(4)
		if len(lengthbytes) < 4: raise pwrtls_exception('Invalid frame.')

		# delim start check
		delim_start = self._recv(1)
		if delim_start != ':': raise pwrtls_exception('Invalid frame.')

		framelen = struct.unpack('!I', lengthbytes)[0]
		buf = ''
		while len(buf) < framelen:
			tmp = self._recv(min(BUFSIZE, framelen-len(buf)))
			buf += tmp

		# delim end check
		delim_end = self._recv(1)
		if delim_end != ',': raise pwrtls_exception('Invalid frame.')

		return buf

	def _recv(self, length):
		d = self._sock.recv(length)
		if not d: raise pwrtls_closed()
		return d

	def recv(self, buflen):
		if buflen <= len(self.rbuf):
			r, self.rbuf = self.rbuf[:buflen], self.rbuf[buflen:]
			return r

		r, buflen = self.rbuf, buflen-len(self.rbuf)
		f = self._recv_frame()
		tmp = self._open_message(f)
		r, self.rbuf = r+tmp[:buflen], tmp[buflen:]
		return r

	def send(self, data):
		m = self._message(data)
		self._send_frame(m)
		return len(data)

	def _send_frame(self, data):
		data = struct.pack('!I', len(data)) + ':' + data + ','
		self._sock.sendall(data)

	def do_handshake(self):
		raise Exception("Implement in subclass!")

	def _message(self, data):
		m = { 
			'box': _b(nacl.crypto_box(data, snonce(self.shortnonce), self.remote_shortpub, self.shortpriv)), 
			'n': self.shortnonce
		}

		self.shortnonce += 2
		return bson.BSON.encode(m)

	def _open_message(self, data):
		box, tmpnonce = from_bson(data, 'box', 'n')
		opened = nacl.crypto_box_open(box, snonce(tmpnonce), self.remote_shortpub, self.shortpriv)
		return opened

	def close(self):
		self._sock.close()

	def write(self, data):
		return self.send(data)

	def read(self):
		return self.recv(BUFSIZE)

class PTLS_Server(PTLS_Socket):

	def do_handshake(self):
		"""Perform a PTLS handshake."""
		self.shortnonce = 4

		# first frame is client_hello, with his short-term pubkey
		data = self._recv_frame()
		self.remote_shortpub = from_bson(data, 'spub')

		# now send our hello message with short-term pubkey
		self._send_frame(self.serverhello())

		# receive verification message for authenticating the short-term key
		data = self._recv_frame()
		opened = nacl.crypto_box_open(data, snonce(3), self.remote_shortpub, self.shortpriv)
		remote_longpub, vbox, vnonce = from_bson(opened, 'lpub', 'v', 'vn')

	def serverhello(self):
		m = {
			'box': _b(nacl.crypto_box(
				str(bson.BSON.encode({
					'spub': _b(self.shortpub),
				})),
				snonce(2), self.remote_shortpub, self.privkey)),
			'lpub': _b(self.pubkey),
		}
		return bson.BSON.encode(m)


class PTLS_Client(PTLS_Socket):

	def do_handshake(self):
		"""Perform a PTLS handshake."""
		self.shortnonce = 5

		self._send_frame(self.clienthello())

		# receive server hello with his short-term pubkey
		data = self._recv_frame()
		box, self.remote_longpub = from_bson(data, 'box', 'lpub')
		srvhello = nacl.crypto_box_open(box, snonce(2), self.remote_longpub, self.shortpriv)
		self.remote_shortpub = from_bson(srvhello, 'spub')

		# send verification message authenticating our short-term key with our long-term one
		self._send_frame(self.clientverify())

	def clienthello(self):
		m = {
			'spub': _b(self.shortpub)
		}
		return bson.BSON.encode(m)

	def clientverify(self):
		self.nonce += 1

		vn = lnonce(self.nonce)
		verifybox = _b(nacl.crypto_box(
			self.shortpub, vn, self.remote_longpub, self.privkey
		))

		m = _b(nacl.crypto_box(
			str(bson.BSON.encode({
				'lpub': _b(self.pubkey),
				'v': verifybox,
				'vn': _b(vn),
			})),
			snonce(3), self.remote_shortpub, self.shortpriv
		))
		return m


def wrap_socket(sock, pubkey=None, privkey=None, nonce=None,
				server_side=False):
	"""Create a new :class:`PTLS_Socket` instance."""
	if server_side:
		return PTLS_Server(sock, pubkey=pubkey, privkey=privkey, nonce=nonce)
	else:
		return PTLS_Client(sock, pubkey=pubkey, privkey=privkey, nonce=nonce)


def verify_remote_longterm_pubkey():
	# we can only open this if we actually have the clients long-term key.
	if self.rpub:
		if str(remote_longpub) != self.rpub: raise pwrtls_exception('remote long-term key mismatch.')
		boxshort = nacl.crypto_box_open(vbox, vnonce, self.rpub, self.privkey)
		if str(boxshort) != str(self.remote_shortpub): raise pwrtls_exception('remote short-term key verify failed.')
