#	encdec - Trivial encryption/decryption utility using strong KDF and ciphers
#	Copyright (C) 2019-2020 Johannes Bauer
#
#	This file is part of encdec.
#
#	encdec is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	encdec is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with encdec; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import os
import json
import time
import struct
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
_backend = default_backend()

class EncryptedFile():
	_LENGTHFIELD = struct.Struct("< L")
	_DKLENS = {
		"AES256-GCM":		32,
	}

	def __init__(self, header, encrypted_payload):
		assert(isinstance(header, dict))
		assert(isinstance(encrypted_payload, bytes))
		self._header = header
		self._encrypted_payload = encrypted_payload

	def write(self, filename):
		with open(filename, "wb") as f:
			header_bin = json.dumps(self._header).encode("utf-8")
			lengthfield = self._LENGTHFIELD.pack(len(header_bin))
			f.write(lengthfield)
			f.write(header_bin)
			f.write(self._encrypted_payload)

	@classmethod
	def read(cls, filename):
		with open(filename, "rb") as f:
			lengthfield = f.read(cls._LENGTHFIELD.size)
			(lengthfield, ) = cls._LENGTHFIELD.unpack(lengthfield)
			header_bin = f.read(lengthfield)
			header = json.loads(header_bin.decode("utf-8"))
			encrypted_payload = f.read()
			return cls(header, encrypted_payload)

	@classmethod
	def kdf(cls, kdf, key, salt = None, dklen = None, verbose = False):
		assert(isinstance(key, bytes))
		if salt is None:
			salt = os.urandom(32)
		if dklen is None:
			dklen = kdf["dklen"]
		meta = {
			"name":		kdf["name"],
			"salt":		salt.hex(),
			"dklen":	dklen,
		}
		t0 = time.time()
		if kdf["name"] == "scrypt":
			N = kdf.get("N", 1024 * 1024)
			r = kdf.get("r", 8)
			p = kdf.get("p", 1)
			meta.update({
				"N":	N,
				"r":	r,
				"p":	p,
			})
			scrypt = Scrypt(salt = salt, length = dklen, n = N, r = r, p = p, backend = _backend)
			dkey = scrypt.derive(key)
		else:
			raise NotImplementedError(kdf["name"])
		t1 = time.time()
		if verbose:
			print("Key derivation took %.3f sec" % (t1 - t0))
		return (meta, dkey)

	def decrypt(self, key, verbose = False):
		assert(isinstance(key, bytes))
		(meta, dkey) = self.kdf(self._header["kdf"], key, salt = bytes.fromhex(self._header["kdf"]["salt"]), verbose = verbose)
		if self._header["cipher"]["name"] == "AES256-GCM":
			iv = bytes.fromhex(self._header["cipher"]["iv"])
			decryptor = Cipher(algorithms.AES(dkey), modes.GCM(iv), backend = _backend).decryptor()
			plaintext = decryptor.update(self._encrypted_payload)
			tag = bytes.fromhex(self._header["cipher"]["tag"])
			decryptor.finalize_with_tag(tag)
		else:
			raise NotImplementedError(self._header["cipher"]["name"])
		return plaintext

	@classmethod
	def encrypt(cls, plaintext, kdf, cipher, key, verbose = False):
		if cipher not in cls._DKLENS:
			raise NotImplementedError(cipher)

		kdf = dict(kdf)
		kdf["dklen"] = cls._DKLENS[cipher]
		if cipher == "AES256-GCM":
			(meta, dkey) = cls.kdf(kdf, key, verbose = verbose)
			iv = os.urandom(16)
			encryptor = Cipher(algorithms.AES(dkey), modes.GCM(iv), backend = _backend).encryptor()
			ciphertext = encryptor.update(plaintext) + encryptor.finalize()
			tag = encryptor.tag
			return cls(header = {
				"kdf":		meta,
				"cipher": {
					"name":		cipher,
					"iv":		iv.hex(),
					"tag":		tag.hex(),
				},
			}, encrypted_payload = ciphertext)
		else:
			raise NotImplementedError(cipher)

if __name__ == "__main__":
	x = EncryptedFile.encrypt(plaintext = b"foobar", kdf = { "name": "scrypt", "N": 1024 }, cipher = "AES256-GCM", key = b"key")
	x.write("out.bin")

	y = EncryptedFile.read("out.bin").decrypt(b"key")
	print(y)
