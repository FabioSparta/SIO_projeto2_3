
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class ClientInfo:
    def __init__(self):
        self.file_key = None
        self.cert_privk = None
        self.id = None
        self.suite = None
        self.parameters = None
        self.privK = None
        self.pubK = None
        self.pubKPEM = None
        self.svPubK = None
        self.sharedK = None
        self.security = None
        self.authentication_cert = None

    def GenerateExchangeParameters(self):
        if self.suite[0] == "DH":
            self.DH_Exchange()

            
        
    def DH_Exchange(self):
        self.parameters = dh.generate_parameters(generator=2, key_size=512)
        self.privK = self.parameters.generate_private_key()
        self.pubK = self.privK.public_key()
        self.pubKPEM =self.pubK.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    

    def GenerateSharedK(self,svPubK):
        self.svPubK = load_pem_public_key(svPubK)
        self.sharedK = self.privK.exchange(self.svPubK)

    def get_p_g(self):
        return self.parameters.parameter_numbers().p, self.parameters.parameter_numbers().g


        
      

