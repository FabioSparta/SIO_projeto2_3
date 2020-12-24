
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class ServerInfo:
    def __init__(self):
        self.suite=None
        self.parameters=None
        self.privK=None
        self.pubK=None
        self.pubKPEM=None
        self.clientPubK=None
        self.sharedK=None

    def GenerateSharedK(self,p,g,clientPubk):
        pn= dh.DHParameterNumbers(int(p[0]), int(g[0]))

        self.parameters = pn.parameters()
        self.clientPubK = load_pem_public_key(clientPubk[0])
        self.privK = self.parameters.generate_private_key()
        self.pubK = self.privK.public_key()
        self.pubKPEM = self.pubK.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.sharedK = self.privK.exchange(self.clientPubK)
    

        
      

