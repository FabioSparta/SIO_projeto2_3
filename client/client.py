import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import support_client
import sys

sys.path.insert(1, '/home/fabiosparta/Desktop/SIO/Projeto2_3')
import Encryption.algorithms

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)
SERVER_URL = 'http://127.0.0.1:8080'

"""
exchange = ["DH_RSA"]
cyphers = ["AES256", "AES_128", "EDE"]
cypher_mode = ["CBC", "GCM"]
digests = ["SHA256", "SHA512"]

supported_cyphers={'exchange':exchange, "cyphers": cyphers, "cypher_mode": cypher_mode, digests: digests}
"""

cypher_suites = [
    "DH_RSA_AES256_CBC_SHA512",
    "DH_RSA_AES256_CBC_SHA256",
    "DH_RSA_EDE_CBC_SHA256",
    "DH_RSA_EDE_CBC_SHA512",
    "DH_RSA_EDE_GCM_SHA256",
    "DH_RSA_AES256_GCM_SHA256",
    "DH_RSA_AES256_GCM_SHA512",
    "DH_RSA_EDE_GCM_SHA512"
]

cypher_suitesJ = {'List': cypher_suites}


########## FUNCTIONS START ##############
def GetMusicList():
    # Request MusicList to server
    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")

    media_list = req.json()

    # Print MusicList
    print("MEDIA CATALOG\n")
    idx = 0
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
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


def PlayMusic(media_list, selection, client):
    # Example: Download first file
    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder or in alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Initialize encryptor
    """decrypter = Encryption.algorithms.Algorythms()
    decrypter.name = client.suite[2]
    decrypter.mode = client.suite[3]
    decrypter.AdaptKey(client.sharedK)"""
    #######

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()

        # TODO: Process chunk
        """
        decrypted_chunk = decrypter.Decryption(chunk['data'], chunk['iv'])
        decrypted_chunk = decrypted_chunk.json()
        data = binascii.a2b_base64(decrypted_chunk['data'].encode('latin'))
        """
        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break


def NegotiateSuite():
    req = requests.post(f'{SERVER_URL}/api/suite', data=cypher_suitesJ)
    if req.status_code == 200:
        print("Suite Negotiation done")

    choosen_suite = req.json().get('data')

    if choosen_suite is not None:
        return choosen_suite
    else:
        print("Something went wrong and Suite returned is None")
        return None


def ExchangeKeys(client):
    client.GenerateExchangeParameters()

    # send client parameters and pub_key to server
    p, g = client.get_p_g()
    msg = {'p': p, 'g': g, 'pubK': client.pubKPEM}
    req = requests.post(f'{SERVER_URL}/api/key', msg)
    if req.status_code == 200:
        print("Sent parameters to server successfully!")

    # get server response with his pubkey
    msg = req.json()
    client.GenerateSharedK(binascii.a2b_base64(msg['pubK'].encode('latin')))


def Authenticate():
    req = requests.get(f'{SERVER_URL}/api/auth')
    if req.status_code == 200:
        print("Api/auth not yet implemented")


########## FUNCTIONS END #################


def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")
    # Class to save info on the connection keys etc.
    client = support_client.ClientInfo()

    # Start Connecting
    client.suite = NegotiateSuite()
    print(client.suite)
    ExchangeKeys(client)
    # Authenticate()
    selection, media_list = GetMusicList()
    PlayMusic(media_list, selection, client)


if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)
