import os
import json
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
	def kdf(cls, kdf, key, salt = None, dklen = None):
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
		if kdf["name"] == "scrypt":
			N = kdf.get("N", 1024 * 1024)
			r = kdf.get("r", 8)
			p = kdf.get("p", 1)
			meta.update({
				"N":	N,
				"r":	r,
				"p":	p,
			})
			scrypt = Scrypt(salt = salt, length = dklen, n = N, r = r, p = 1, backend = _backend)
			dkey = scrypt.derive(key)
		else:
			raise NotImplementedError(kdf["name"])
		return (meta, dkey)

	def decrypt(self, key):
		assert(isinstance(key, bytes))
		(meta, dkey) = self.kdf(self._header["kdf"], key, salt = bytes.fromhex(self._header["kdf"]["salt"]))
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
	def encrypt(cls, plaintext, kdf, cipher, key):
		if cipher not in cls._DKLENS:
			raise NotImplementedError(cipher)

		kdf = dict(kdf)
		kdf["dklen"] = cls._DKLENS[cipher]
		if cipher == "AES256-GCM":
			(meta, dkey) = cls.kdf(kdf, key)
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
