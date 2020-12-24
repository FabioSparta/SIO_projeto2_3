import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Algorythms:

    def __init__(self):
        self.key = None
        self.name = None
        self.mode = None

    # Adapt Key to Algorithm
    def AdaptKey(self, key):
        if self.name == "AES256":
            self.key = self.Derive_key(key, 256)
        elif self.name == "AES128":
            self.key = self.Derive_key(key, 128)
        elif self.name == "3DES":
            self.key = self.Derive_key(key, 128)

    def Derive_key(self, key, size):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=size,
            salt=None,
            info=None, ).derive(self.key)

    # Execute Encryption
    def Encryption(self, msg):
        if self.name == "AES256":
            return self.E_AES_256(msg)
        elif self.name == "AES128":
            return self.E_AES_128(msg)
        elif self.name == "3DES":
            return self.E_AES_128(msg)
        else:
            print("A not supported algorithm was choosen")

    # Execute Decryption
    def Decryption(self, msg):
        if self.name == "AES256":
            return self.D_AES_256(msg)
        elif self.name == "AES128":
            return self.D_AES_128(msg)
        elif self.name == "3DES":
            return self.D_3DES(msg)

    # Encryptions
    def E_AES_256(self, msg):
        iv = os.urandom(16)
        if self.mode == "CBC":
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        elif self.mode == "GCM":
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv))
        else:
            print("A not supported  cypher mode was choosen")
            return

        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        chunks = [msg[i:i + 16] for i in range(0, len(msg), 16)]
        msg = bytearray()
        for chunk in chunks:
            block = str.encode(chunk)  # convert to bytes
            if len(block) < 16:  # It's the last msg => Add Padding
                qty = 16 - len(block)
                block = padder.update(bytes([qty] * qty))  # exemplo qty=3 => update(bytes([3,3,3]))
                msg += encryptor.update(bytes(block, encoding='utf-8')) + encryptor.finalize()
            else:
                msg += encryptor.update(bytes(msg, enconding='utf-8')) + encryptor.finalize()
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(msg)
        print(iv)
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        return msg.decode(), iv

    def E_3DES(self, msg):
        print("Not yet implemented")

    def E_AES_128(self, msg):
        print("Not yet implemented")

    def D_AES_256(self, msg, iv):
        if self.mode == "CBC":
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        elif self.mode == "GCM":
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv))
        else:
            print("A not supported  cypher mode was choosen")
            return

        decrypter = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        chunks = [msg[i:i + 16] for i in range(0, len(msg), 16)]
        msg = bytearray()
        for x in range(16):
            block = str.encode(chunks[x])  # convert to bytes
            decrypted = decrypter.update(bytes(block, encoding='utf-8')) + decrypter.finalize()
            if x == 15:
                decrypted = unpadder.update(decrypted)
            msg += decrypted
        return msg.decode()

    def D_3DES(self, msg):
        print("Not yet implemented")

    def D_AES_128(self, msg):
        print("Not yet implemented")
