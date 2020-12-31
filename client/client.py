import inspect
from datetime import datetime

import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import PyKCS11
import binascii
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import support_client

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
import Shared.algorithms

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)
SERVER_URL = 'http://127.0.0.1:8080'

cypher_suites = [
    "DH_RSA_AES256_CBC_SHA512",
    "DH_RSA_AES256_CBC_SHA256",
    "DH_RSA_AES256_GCM_SHA256",
    "DH_RSA_AES256_GCM_SHA512",
    "DH_RSA_AES128_CBC_SHA512",
    "DH_RSA_AES128_CBC_SHA256",
    "DH_RSA_AES128_GCM_SHA256",
    "DH_RSA_AES128_GCM_SHA512",
    "DH_RSA_EDE_CBC_SHA256",
    "DH_RSA_EDE_CBC_SHA512",
]
cypher_suitesJ = {'List': cypher_suites}


########## FUNCTIONS START ##############
def GetMusicList(client):
    # Request MusicList to server
    req = requests.get(f'{SERVER_URL}/api/list?user_id={client.id}')
    if req.status_code == 200:
        print("Got Server List")
        media_list = req.json()

        data = binascii.a2b_base64(media_list['data'].encode('latin'))
        iv = binascii.a2b_base64(media_list['iv'].encode('latin'))
        tag = binascii.a2b_base64(media_list['tag'].encode('latin'))
        mac_received = binascii.a2b_base64(media_list['mac'].encode('latin'))
        mac_data_received = client.security.Gen_Mac(data)

        if mac_received != mac_data_received:
            print("The data received is corrupted.")
            sys.exit(-1)

        decrypted_data = client.security.Decryption(data, iv, tag)
        client.security.RotateKey(decrypted_data)
        media_list = eval(decrypted_data.decode())

        # Print MusicList
        print("MEDIA CATALOG\n")
        idx = 0
        for item in media_list:
            print(f'{idx} - {item["name"]}')
            idx += 1
            print("----")

        # Client chooses music from list
        while True:
            selection = input("Select a media file number (q to quit): ")
            if selection.strip() == 'q':
                sys.exit(0)

            if not selection.isdigit():
                continue

            selection = int(selection)
            if 0 <= selection < len(media_list):
                return selection, media_list
    else:
        print("Failed to get List")
        sys.exit(-1)


def checkLicense(client, media_list, selection):
    media_item = media_list[selection]
    msg = {'id': client.id, 'music': media_item['name']}
    # msg = EncryptMsg(client, str(msg))

    req = requests.post(f'{SERVER_URL}/api/license', data=msg)

    if req.status_code == 200:
        answer = req.json()
        print(answer["info"])
    else:
        answer = req.json()
        print(answer["info"])
        print("Run the app again to get a new license for the music:" + media_item['name'])
        sys.exit(-1)


def playMusic(media_list, selection, client):
    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder or in alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}&user_id={client.id}')
        chunk = req.json()

        # Process chunk
        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        iv = binascii.a2b_base64(chunk['iv'].encode('latin'))
        tag = binascii.a2b_base64(chunk['tag'].encode('latin'))
        mac_received = binascii.a2b_base64(chunk['mac'].encode('latin'))
        mac_data_received = client.security.Gen_Mac(data)

        if mac_received != mac_data_received:
            print("The data received is corrupted.")
            sys.exit(-1)

        decrypted_data = client.security.Decryption(data, iv, tag)
        client.security.RotateKey(decrypted_data)

        try:
            proc.stdin.write(decrypted_data)
        except:
            break



def SendCertificate(client):
    f = open('clientCert.pem', 'rb')
    pem_data = f.read()
    client.security.my_cert = pem_data
    msg = {'cert_pem': pem_data}

    req = requests.post(f'{SERVER_URL}/api/auth', msg)
    if req.status_code == 200:
        print("Sen cert_pem to server --DONE")
        my_id = req.json().get('user_id')
        print("ID:" + str(my_id))
        return my_id
    else:
        print("Your certificate is invalid --FAILED")
        sys.exit(-1)


def NegotiateSuite(client):
    req = requests.post(f'{SERVER_URL}/api/suite', data={'List': cypher_suites, 'user_id': client.id})
    if req.status_code == 200:
        print("Suite Negotiation --DONE")
        chosen_suite = req.json().get('data')
        client.suite = chosen_suite
        print("SUITE:" + str(client.suite))
    else:
        print("Suite Negotiation --FAILED")
        sys.exit(-1)


def ExchangeKeys(client):
    client.GenerateExchangeParameters()
    # send client parameters and pub_key to server
    p, g = client.get_p_g()

    signature = client.cert_privk.sign(
        client.pubKPEM,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    msg = {'user_id': client.id, 'p': p, 'g': g, 'pubK': client.pubKPEM, 'signature': signature}
    req = requests.post(f'{SERVER_URL}/api/key', msg)
    if req.status_code == 200:
        print("Parameters sent to server --DONE")

        # get server response with his pubkey
        msg = req.json()
        signature = binascii.a2b_base64(msg['signature'].encode('latin'))
        serverPubK = binascii.a2b_base64(msg['pubK'].encode('latin'))
        try:
            client.security.other_cert.public_key().verify(
                signature,
                serverPubK,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            client.GenerateSharedK(serverPubK)
            client.security.name = client.suite[2]
            client.security.mode = client.suite[3]
            client.security.AdaptKey(client.sharedK)
            client.security.CreateDigest(client.suite[4])
        except:
            print("Invalid Signature on Server's DH pubKey --FAILED")
            sys.exit(-1)
    else:
        print("The Signature you sent didn't match the DH pubKey ")
        sys.exit(-1)


def RequestCertificate(client):
    req = requests.get(f'{SERVER_URL}/api/auth')
    if req.status_code == 200:
        print("Got server certificate --DONE")

    msg = req.json()
    pem_data = binascii.a2b_base64(msg['cert_pem'].encode('latin'))
    cert = x509.load_pem_x509_certificate(pem_data)
    #cert.public_key().
    client.security.server_cert = cert


def ValidateCertificate(client):
    client.security.LoadTrustedCA()
    if client.security.VerifyCert(client.security.server_cert):
        print("Valid Certificate --DONE")
    else:
        print("The server Certificate is not valid. Interrupting connection..")
        sys.exit(-1)




def EncryptMsg(client, msg):
    encrypted_data, iv, tag = client.security.Encryption(msg)
    mac = client.security.Gen_Mac(encrypted_data)
    client.security.RotateKey(msg)

    msg = {'data': encrypted_data, 'mac': mac, 'iv': iv,
           'tag': tag, 'user_id': client.id }
    return msg

def SendCC(client):
    authentication_cert = None
    try:
        lib = '/usr/local/lib/libpteidpkcs11.so'
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        slots = pkcs11.getSlotList()

        my_slot = slots[0]
        session = pkcs11.openSession(my_slot)
        all_attr = list(PyKCS11.CKA.keys())
        all_attr = [e for e in all_attr if isinstance(e, int)]  # Filter attributes

        for obj in session.findObjects():
            # Get object attributes
            attr = session.getAttributeValue(obj, all_attr)
            # Create dictionary with attributes
            attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
            # print('Label: ', attr['CKA_LABEL'])
            if attr['CKA_LABEL'] == 'CITIZEN AUTHENTICATION CERTIFICATE':
                authentication_cert = bytes(attr['CKA_VALUE'])
                client.authentication_cert = authentication_cert

    except Exception as e:
        print("You must use your citizen card for authentication. --FAILED")
        sys.exit(-1)

    msg = EncryptMsg(client, authentication_cert)
    req = requests.post(f'{SERVER_URL}/api/cc', data=msg)
    if req.status_code == 200:
        print("Sent CC certificate --DONE")
    else:
        print("Unknown CC --FAILED")
        print("NOTE FOR THE TEACHER: Put your CC's authentication certificate inside the folder 'server/CCs'.")
        sys.exit(-1)

def LoadPrivK(client):
    with open('clientCert.pk8', 'rb') as file:
        f = Fernet(client.file_key)
        decrypted_text = f.decrypt(file.read())
        return decrypted_text

########## FUNCTIONS END #################


def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")
    # Class to save info on the connection keys etc.
    client = support_client.ClientInfo()
    client.file_key = "qCI6beqkRe53E3n11iF6q0hMWgiREII1EJCOPoQUnL8=".encode()
    client.security = Shared.algorithms.Algorythms()
    client.cert_privk = serialization.load_pem_private_key(LoadPrivK(client), password=None)

    # Ask for server certificate
    RequestCertificate(client)
    ValidateCertificate(client)

    # Send My Certificate
    client.id = SendCertificate(client)

    # Negotiate Suites
    NegotiateSuite(client)
    ExchangeKeys(client)

    # Send My CC encrypted
    SendCC(client)

    # Start using Music_App
    while True:
        selection, media_list = GetMusicList(client)
        checkLicense(client, media_list, selection)
        playMusic(media_list, selection, client)


if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)
