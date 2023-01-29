###############################################################################
#	 arc4.py implements arc4 encrypt/decrypt class for Python
#	 Copyright (C) 2005	 Hajime Nakagami<nakagami@da2.so-net.ne.jp>
#
#	 based on ARC4.c from "the Python Cryptography Toolkit,
#	 (see http://cvs.sourceforge.net/viewcvs.py/pycrypto/crypto/src/ARC4.c) 
#	 written by	 A.M. Kuchling"
#
#	 This library is free software; you can redistribute it and/or
#	 modify it under the terms of the GNU Lesser General Public
#	 License as published by the Free Software Foundation; either
#	 version 2.1 of the License, or (at your option) any later version.
#
#	 This library is distributed in the hope that it will be useful,
#	 but WITHOUT ANY WARRANTY; without even the implied warranty of
#	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#	 Lesser General Public License for more details.
#
#	 You should have received a copy of the GNU Lesser General Public
#	 License along with this library; if not, write to the Free Software
#	 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#=============================================================================

"""
arc4 encoding and decoding.
>>> import string
>>> from arc4 import Arc4
>>> a1 = Arc4('a key')
>>> enc = a1.translate('plain text')
>>> [hex(ord(c)) for c in enc]
['0x4b', '0x4b', '0xdc', '0x65', '0x2', '0xb3', '0x8', '0x17', '0x48', '0x82']
>>> a2 = Arc4('a key')
>>> a2.translate(enc)
'plain text'
>>>
draft-kaukonen-cipher-arcfour-03.txt Appendix A
A-1.
>>> ps = (0, 0, 0, 0, 0, 0, 0, 0)
>>> ks = (0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef)
>>> p = string.join([chr(c) for c in ps], '')
>>> k = string.join([chr(c) for c in ks], '')
>>> a3 = Arc4(k)
>>> enc = a3.translate(p)
>>> [hex(ord(c)) for c in enc]
['0x74', '0x94', '0xc2', '0xe7', '0x10', '0x4b', '0x8', '0x79']
>>>
A-2.
>>> ps = (0xdc, 0xee, 0x4c, 0xf9, 0x2c)
>>> ks = (0x61, 0x8a, 0x63, 0xd2, 0xfb)
>>> p = string.join([chr(c) for c in ps], '')
>>> k = string.join([chr(c) for c in ks], '')
>>> a4 = Arc4(k)
>>> enc = a4.translate(p)
>>> [hex(ord(c)) for c in enc]
['0xf1', '0x38', '0x29', '0xc9', '0xde']
>>>
"""

class Arc4:
	def __init__(self, key):
		state = list(range(256))
		index1 = 0
		index2 = 0

		for i in range(256):
			index2 = (ord(key[index1]) + state[i] + index2) % 256
			(state[i], state[index2]) = (state[index2], state[i])
			index1 = (index1 + 1) % len(key)

		self.state = state
		self.x = 0
		self.y = 0

	def translate(self, plain):
		state = self.state
		enc=''
		for i in range(len(plain)):
			self.x = (self.x + 1) % 256
			self.y = (self.y + state[self.x]) % 256
			(state[self.x], state[self.y]) = (state[self.y], state[self.x])
			xorIndex = (state[self.x]+state[self.y]) % 256
			enc += chr(ord(plain[i]) ^ state[xorIndex])
		return enc

	if __name__ == "__main__":
		import doctest
		doctest.testmod()

