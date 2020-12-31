import inspect
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
import Shared.algorithms

class ServerInfo:
    def __init__(self):
        self.security = Shared.algorithms.Algorythms()
        self.current_music = bytearray()
        self.serial_number = None
        # DH
        self.suite = None
        self.parameters = None
        self.privK = None
        self.pubK = None
        self.pubKPEM = None
        self.clientPubK = None
        self.sharedK = None

    def generateSharedK(self, p, g, clientPubk):
        pn = dh.DHParameterNumbers(int(p[0]), int(g[0]))

        self.parameters = pn.parameters()
        self.clientPubK = load_pem_public_key(clientPubk[0])
        self.clientPubKPEM = clientPubk[0]
        self.privK = self.parameters.generate_private_key()
        self.pubK = self.privK.public_key()
        self.pubKPEM = self.pubK.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.sharedK = self.privK.exchange(self.clientPubK)