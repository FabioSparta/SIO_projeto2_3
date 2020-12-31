#!/usr/bin/env python
import binascii
import json
import logging
import math
import os

from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from twisted.internet import reactor
from twisted.web import server, resource

import random
import support_server

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

## GLOBAL VARIABLES ##
cypher_suites = [
    "DH_RSA_AES128_GCM_SHA512",
    "DH_RSA_AES128_GCM_SHA256",
    "DH_RSA_AES128_CBC_SHA256",
    "DH_RSA_AES128_CBC_SHA512",
    "DH_RSA_EDE_CBC_SHA256",
    "DH_RSA_AES256_CBC_SHA256",
    "DH_RSA_AES256_GCM_SHA256",
    "DH_RSA_AES256_GCM_SHA512",
    "DH_RSA_AES256_CBC_SHA512",
    "DH_RSA_EDE_CBC_SHA512",
]

CATALOG = {'898a08080d1840793122b7e118b27a95d117ebce':
    {
        'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
        'album': 'Upbeat Ukulele Background Music',
        'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
        'duration': 360 + 33,
        'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
        'file_size': 3407202
    },
    'PerfectTime':
        {
            'name': '7DS - PerfectTime',
            'album': '7DS OST',
            'description': 'Theme song of 7 Deadly Sins',
            'duration': 4 * 60 + 43,
            'file_name': 'PerfectTime.mp3',
            'file_size': 6814160
        },
    'Domestic na Kanojo Opening':
        {
            'name': 'Domestic na Kanojo Opening Cover by Raon Lee',
            'album': 'Domestic na Kanojo',
            'description': 'Domestic na Kanojo opening Cover by Raon Lee',
            'duration': 60 + 28,
            'file_name': 'Domestic na Kanojo OP - Kawaki wo AmekuCover by Raon Lee.mp3',
            'file_size': 9999999
        },
}

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4


class MediaServer(resource.Resource):
    isLeaf = True

    def __init__(self):
        super().__init__()
        self.filesKey = "7fPdeSrfCQ2iGrPMCqQ4pesGpproTg26bC9wNjJJE0E=".encode()
        self.privKfile_key = "eoRLh7Z3tDMafUbvsk4OA_YmdNHRgbL-aoWcBKOkbuc=".encode()
        self.ids = -1
        self.users_dic = {}
        self.privK = serialization.load_pem_private_key(self.LoadPrivK(), password=None)

    def LoadPrivK(self):
        with open('Server.pk8', 'rb') as file:
            f = Fernet(self.privKfile_key)
            decrypted_text = f.decrypt(file.read())
            return decrypted_text

    def authenticateClient(self, request, new_id):
        self.users_dic[new_id] = support_server.ServerInfo()
        self.users_dic[new_id].security.LoadTrustedCA()
        cert = x509.load_pem_x509_certificate(request.args.get(b'cert_pem')[0])
        if self.users_dic[new_id].security.VerifyCert(cert):
            print("Valid Client Certificate")
            return json.dumps({'verification': 'Certificate approved.', 'user_id': new_id}, indent=4).encode('latin')
        else:
            print("Invalid Client Certificate")
            request.setResponseCode(401)
            return json.dumps({'error': 'Your certificate is invalid.'}, indent=4).encode('latin')

    def negotiateSuite(self, request):
        client_list = request.args.get(b'List')
        client_list2 = [a.decode('ascii') for a in client_list]
        common_suites = [suite for suite in cypher_suites if suite in client_list2]
        request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
        if len(common_suites) > 0:
            user_id = int(request.args.get(b'user_id')[0])
            print("Chosen suite:" + common_suites[random.randint(0, len(common_suites) - 1)])
            self.users_dic[user_id].suite = common_suites[random.randint(0, len(common_suites) - 1)].split("_")
            return json.dumps({'data': self.users_dic[user_id].suite, 'user_id': user_id}).encode('latin')
        else:
            print("No common suites found.")
            return json.dumps({'error': 'No cypher Suite Selected.'}).encode('latin')

    def negotiateKeys(self, request):
        user_id = int(request.args.get(b'user_id')[0])
        p = request.args.get(b'p')
        g = request.args.get(b'g')
        clientPubk = request.args.get(b'pubK')
        clientPubK_signature = request.args.get(b'signature')[0]
        self.users_dic[user_id].generateSharedK(p, g, clientPubk)

        request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
        if self.users_dic[user_id].pubK is not None:
            try:
                self.users_dic[user_id].security.other_cert.public_key().verify(
                    clientPubK_signature,
                    self.users_dic[user_id].clientPubKPEM,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception as e:
                print(e)
                request.setResponseCode(401)
                return json.dumps({'error': 'pubK Signature is invalid.'}).encode('latin')

            self.users_dic[user_id].security.name = self.users_dic[user_id].suite[2]
            self.users_dic[user_id].security.mode = self.users_dic[user_id].suite[3]
            self.users_dic[user_id].security.AdaptKey(self.users_dic[user_id].sharedK)
            self.users_dic[user_id].security.CreateDigest(self.users_dic[user_id].suite[4])
            signature = self.privK.sign(
                self.users_dic[user_id].pubKPEM,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            return json.dumps(
                {'pubK': binascii.b2a_base64(self.users_dic[user_id].pubKPEM).decode('latin').strip(),
                 'signature': binascii.b2a_base64(signature).decode('latin').strip()}).encode('latin')
        else:
            return json.dumps({'error': 'Some error ocurred generating the pub key.'}).encode('latin')

    def sendCertificate(self, request):
        print("sending certificate")
        f = open('Server.pem', 'rb')
        pem_data = f.read()

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        if pem_data is not None:
            return json.dumps(
                {
                    'cert_pem': binascii.b2a_base64(pem_data).decode('latin').strip(),
                }
            ).encode('latin')

        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    def verifyCC(self, request):
        user_id = int(request.args.get(b'user_id')[0])
        clientCC = request.args.get(b'data')[0]
        iv = request.args.get(b'iv')[0]
        tag = request.args.get(b'tag')[0]
        mac_received = request.args.get(b'mac')[0]
        mac_data_received = self.users_dic[user_id].security.Gen_Mac(clientCC)

        if mac_received != mac_data_received:
            print("The data received about clientCC is corrupted.")
            return json.dumps({'error': 'corrupted_data'}, indent=4).encode('latin')

        clientCC = self.users_dic[user_id].security.Decryption(clientCC, iv, tag)
        self.users_dic[user_id].security.RotateKey(clientCC)

        clientCC = x509.load_der_x509_certificate(clientCC)
        self.users_dic[user_id].serial_number = clientCC.serial_number

        for filename in os.listdir('CCs'):
            with open(os.path.join('CCs', filename), 'rb') as file:
                cc = file.read()
                cc = x509.load_der_x509_certificate(cc)
                if clientCC == cc:
                    return json.dumps({'verification': 'Valid'}, indent=4).encode('latin')

        # Didn't find this user
        request.setResponseCode(401)
        print("The client CC is invalid.")
        return json.dumps({'verification': 'Unknown user'}, indent=4).encode('latin')

    # Send the list of media files to clients
    def do_list(self, request):
        user_id = int(request.args.get(b'user_id', [None])[0])
        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
            })

        data = str(media_list).encode()

        encrypted_data, iv, tag = self.users_dic[user_id].security.Encryption(data)
        mac = self.users_dic[user_id].security.Gen_Mac(encrypted_data)
        self.users_dic[user_id].security.RotateKey(data)

        binascii.b2a_base64(encrypted_data).decode('latin').strip()
        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        #return json.dumps(media_list, indent=4).encode('latin')
        return json.dumps(
            {
                'data': binascii.b2a_base64(encrypted_data).decode('latin').strip(),
                'iv': binascii.b2a_base64(iv).decode('latin').strip(),
                'tag': binascii.b2a_base64(tag).decode('latin').strip(),
                'mac': binascii.b2a_base64(mac).decode('latin').strip(),
            }, indent=4
        ).encode('latin')

    def License(self, request):
        print("Handling License")
        music = request.args.get(b'music')[0].decode('ascii')
        user_id = int(request.args.get(b'id')[0])
        user_path = os.path.join('licenses', str(self.users_dic[user_id].serial_number))
        license_path = os.path.join('licenses', str(self.users_dic[user_id].serial_number), music)

        # If there isn't a folder for this user, create it.
        if not os.path.isdir(user_path):
            os.mkdir(user_path)

        # License already exists
        views = 0
        if os.path.isfile(license_path):
            print("Updating license with -1 available views.")
            with open(license_path, 'rb') as file:
                encrypted_data = file.read()
                f = Fernet(self.filesKey)
                licensee = f.decrypt(encrypted_data)
                dic = eval(licensee.decode('UTF-8'))
                if dic["views"] == 0 or datetime.strptime(dic["date_expiration"],
                                                          '%Y-%m-%d %H:%M:%S.%f') < datetime.now():
                    request.setResponseCode(401)
                    os.remove(license_path)
                else:
                    dic["views"] = dic["views"] - 1
                    views = dic["views"]
                    print("Views left:" + str(dic["views"]))
                    with open(license_path, 'wb') as file2:
                        encrypted_data = f.encrypt(str(dic).encode('utf-8'))
                        file2.write(encrypted_data)

                if datetime.strptime(dic["date_expiration"], '%Y-%m-%d %H:%M:%S.%f') < datetime.now():
                    return json.dumps({
                        'info': 'Your license has expired'}).encode('latin')

            return json.dumps({
                'info': 'License for the music: ' + music + " available_views: " + str(views)}).encode('latin')

        # Create License
        else:
            print("Creating license for this user.")
            with open(license_path, 'wb') as file:
                f = Fernet(self.filesKey)
                dic = {"music": music,
                       "views": 2,
                       "date_purchase": str(datetime.now()),
                       "date_expiration": str(datetime.now() + timedelta(days=random.randint(5, 10))),
                       }
                encrypted_data = f.encrypt(str(dic).encode('utf-8'))
                file.write(encrypted_data)
            return json.dumps(
                {'info': 'We created a license for the music: ' + music + ". You have 2 more  views available"}).encode(
                'latin')

    # Send a media chunk to the client
    def do_download(self, request):
        user_id = int(request.args.get(b'user_id', [None])[0])

        logger.debug(f'Download: args: {request.args}')
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')

        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')

        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')
        else:  # It's a valid chunk
            if chunk_id == 0:
                with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as file:
                    encrypted_data = file.read()
                    f = Fernet(self.filesKey)
                    self.users_dic[user_id].current_music = f.decrypt(encrypted_data)

        # Get requested chunk from bytearray (bytearray with the whole music)
        logger.debug(f'Download: chunk: {chunk_id}')
        offset = chunk_id * CHUNK_SIZE
        if offset + CHUNK_SIZE < len(self.users_dic[user_id].current_music):
            data = self.users_dic[user_id].current_music[offset:len(self.users_dic[user_id].current_music)]
        else:
            data = self.users_dic[user_id].current_music[offset:offset + CHUNK_SIZE]

        encrypted_data, iv, tag = self.users_dic[user_id].security.Encryption(data)
        mac = self.users_dic[user_id].security.Gen_Mac(encrypted_data)
        self.users_dic[user_id].security.RotateKey(data)

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(
            {
                'media_id': media_id,
                'chunk': chunk_id,
                'data': binascii.b2a_base64(encrypted_data).decode('latin').strip(),
                'iv': binascii.b2a_base64(iv).decode('latin').strip(),
                'tag': binascii.b2a_base64(tag).decode('latin').strip(),
                'mac': binascii.b2a_base64(mac).decode('latin').strip(),
            }, indent=4
        ).encode('latin')

        # File was not open?
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')
        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)

            elif request.path == b'/api/auth':
                return self.sendCertificate(request)

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')

        if request.path == b'/api/suite':
            return self.negotiateSuite(request)

        elif request.path == b'/api/key':
            return self.negotiateKeys(request)

        elif request.path == b'/api/auth':
            self.ids += 1
            new_id = self.ids
            return self.authenticateClient(request, new_id)

        elif request.path == b'/api/cc':
            self.verifyCC(request)

        elif request.path == b'/api/license':
            return self.License(request)

        return b''


print("Server started")
print("URL is: http://IP:8080")
s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
