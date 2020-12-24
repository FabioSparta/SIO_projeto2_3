#!/usr/bin/env python
import binascii
import json
import logging
import math
import os
from twisted.internet import reactor
from twisted.web import server, resource
import support_server
import sys
sys.path.insert(1, '/home/fabiosparta/Desktop/SIO/Projeto2_3')
import Encryption.algorithms
import random

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

## GLOBAL VARIABLES ##
cypher_suites = [
    "DH_RSA_AES256_CBC_SHA256",
    "DH_RSA_AES256_CBC_SHA512",
    "DH_RSA_AES256_GCM_SHA256",
    "DH_RSA_AES256_GCM_SHA512"
    "DH_RSA_EDE_CBC_SHA256",
    "DH_RSA_EDE_yCBC_SHA512",
    "DH_RSA_EDE_GCM_SHA256",
    "DH_RSA_EDE_GCM_SHA512"
]

CATALOG = {'898a08080d1840793122b7e118b27a95d117ebce':
    {
        'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
        'album': 'Upbeat Ukulele Background Music',
        'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
        'duration': 3 * 60 + 33,
        'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
        'file_size': 3407202
    }
}

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4


#####################


class MediaServer(resource.Resource):
    isLeaf = True

    def __init__(self):
        super().__init__()
        self.server_info = support_server.ServerInfo()

    def NegotiateSuite(self, request):
        """
        exchange = request.args.get(b'exchange')
        cyphers = request.args.get(b'cyphers')
        cypher_mode = request.args.get(b'cypher_mode')
        digests = request.args.get(b'digests')
        """
        client_list = request.args.get(b'List')
        client_list2 = [a.decode('ascii') for a in client_list]
        common_suites = [suite for suite in cypher_suites if suite in client_list2]

        if len(common_suites) > 0:
            print("choosen suite:" + common_suites[0])
            choosen_suite = common_suites[0]
            return choosen_suite
        else:
            print("No common suites found.")
            return None

    # Send the list of media files to clients
    def do_list(self, request):

        # auth = request.getHeader('Authorization')
        # if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'

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

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(media_list, indent=4).encode('latin')

    # Send a media chunk to the client
    def do_download(self, request):
        # Initialize encryptor
        encryptor = Encryption.algorithms.Algorythms()
        encryptor.name = self.server_info.suite[2]
        encryptor.mode = self.server_info.suite[3]
        encryptor.AdaptKey(self.server_info.sharedK)
        #######

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

        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            """
            clear_data = json.dumps(
                {
                    'media_id': media_id,
                    'chunk': chunk_id,
                    'data': binascii.b2a_base64(data).decode('latin').strip()
                }, indent=4
            ).encode('latin')
            encrypted_data, iv = encryptor.Encryption(clear_data)
            return json.dumps(
                {
                    'iv': media_id,
                    'data': encrypted_data
                }
            ).encode('latin')
            """
            return json.dumps(
                {
                    'media_id': media_id,
                    'chunk': chunk_id,
                    'data': binascii.b2a_base64(data).decode('latin').strip()
                }, indent=4
            ).encode('latin')


        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)

            elif request.path == b'/api/key':
                pass

            elif request.uri == 'api/auth':
                print("API/Auth not yet implemented.")

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                print("AA")
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
            self.server_info.suite = self.NegotiateSuite(request).split("_")
            if self.server_info.suite is not None:
                return json.dumps({'data': self.server_info.suite}).encode('latin')
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return json.dumps({'error': 'No cypher Suite Selected.'}).encode('latin')

        elif request.path == b'/api/key':
            p = request.args.get(b'p')
            g = request.args.get(b'g')
            clientPubk = request.args.get(b'pubK')
            self.server_info.GenerateSharedK(p, g, clientPubk)
            if self.server_info.pubK is not None:
                print(self.server_info.sharedK)
                return json.dumps(
                    {'pubK': binascii.b2a_base64(self.server_info.pubKPEM).decode('latin').strip()}).encode('latin')
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return json.dumps({'error': 'Some error ocurred generating the pub key.'}).encode('latin')

        return b''


print("Server started")
print("URL is: http://IP:8080")
s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
