import os
import sys
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding

class Algorythms:

    def __init__(self):
        self.other_cert = None
        self.my_cert = None
        self.shared_key = None
        self.key = None
        self.name = None
        self.mode = None
        self.block_size = None
        self.digest = None
        self.client_CC = None
        self.trusted_ca = None

    # Adapt Key to Algorithm
    def AdaptKey(self, key):
        self.shared_key = key
        if self.name == "AES256":
            self.key = self.Derive_key(key, 32)
            self.block_size = algorithms.AES(self.key).block_size
        elif self.name == "AES128":
            self.key = self.Derive_key(key, 16)
            self.block_size = algorithms.AES(self.key).block_size
        elif self.name == "EDE":
            self.key = self.Derive_key(key, 16)
            self.block_size = algorithms.TripleDES(self.key).block_size

    def Derive_key(self, key, size):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=size,
            salt=None,
            info=None, ).derive(key)

    def Encryption(self, msg):
        if self.name == "AES256" or self.name == "AES128":
            return self.E_AES(msg)
        elif self.name == "EDE":
            return self.E_3DES(msg)
        else:
            print("A not supported algorithm was chosen.")

    def Decryption(self, msg, iv, tag=None):
        if self.name == "AES256" or self.name == "AES128":
            return self.D_AES(msg, iv, tag)
        elif self.name == "EDE":
            return self.D_3DES(msg, iv)
        else:
            print("A not supported algorithm was chosen.")

    # Encryptions
    def E_AES(self, msg):
        iv = os.urandom(16)
        if self.mode == "CBC":
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            xpadding = self.block_size - len(msg) % self.block_size
            if xpadding == 0:
                xpadding == 16
            msg += bytes([xpadding] * xpadding)
            msg = encryptor.update(msg) + encryptor.finalize()
            return msg, iv, b'none'
        elif self.mode == "GCM":
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            msg = encryptor.update(msg) + encryptor.finalize()
            return msg, iv, encryptor.tag
        else:
            print("A not supported  cypher mode for AES was chosen")
            return

    def E_3DES(self, msg):
        iv = os.urandom(8)
        if self.mode == "CBC":
            cipher = Cipher(algorithms.TripleDES(self.key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            xpadding = self.block_size - len(msg) % self.block_size
            if xpadding == 0:
                xpadding == 8
            msg += bytes([xpadding] * xpadding)
            msg = encryptor.update(msg) + encryptor.finalize()
            return msg, iv, b'none'
        else:
            print("A not supported  cypher mode for 3DES was chosen.")
            return

    def D_AES(self, msg, iv, tag=None):
        if self.mode == "CBC":
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        elif self.mode == "GCM":
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag))
        else:
            print("A not supported  cypher mode was chosen.")
            return

        decrypter = cipher.decryptor()
        msg = decrypter.update(msg) + decrypter.finalize()
        if self.mode == "CBC":
            return msg[:-msg[-1]]
        return msg

    def D_3DES(self, msg, iv):
        if self.mode == "CBC":
            cipher = Cipher(algorithms.TripleDES(self.key), modes.CBC(iv))
            decrypter = cipher.decryptor()
            msg = decrypter.update(msg) + decrypter.finalize()
            return msg[:-msg[-1]]
        else:
            print("A not supported  cypher mode was chosen.")
            return

    def CreateDigest(self, digest):
        if digest == "SHA256":
            self.digest = hashes.SHA256()
        elif digest == "SHA512":
            self.digest = hashes.SHA512()

    def Gen_Mac(self, data):
        h = hmac.HMAC(self.key, self.digest)
        h.update(data)
        return h.finalize()

    def RotateKey(self, last_chunk):
        key_len = len(self.key)
        new_key = int.from_bytes(self.key, byteorder=sys.byteorder) ^ \
                  int.from_bytes(last_chunk[:key_len], byteorder=sys.byteorder) ^ \
                  int.from_bytes(self.shared_key[:key_len], byteorder=sys.byteorder)
        self.key = int.to_bytes(new_key, key_len, byteorder=sys.byteorder)


    def LoadTrustedCA(self):
        f = open('../Shared/CAprojeto.crt', 'rb')
        pem_data = f.read()
        self.trusted_ca = x509.load_pem_x509_certificate(pem_data)

    def VerifyCert(self, cert):
        self.trusted_ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        try:
            self.trusted_ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
            if cert.not_valid_after > datetime.now() > cert.not_valid_before:
                self.other_cert = cert
                return True
            else:
                return False
        except:
            return False