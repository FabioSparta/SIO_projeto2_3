import os

from cryptography.fernet import Fernet


def write_key(filename):
    key = Fernet.generate_key()
    with open(filename, "wb") as key_file:
        key_file.write(key)


def load_key(filename):
    return open(filename, "rb").read()


def encrypt(filename, f):
    with open(os.path.join('server', 'catalog', filename), 'rb') as file:
        file_data = file.read()

    encrypted_data = f.encrypt(file_data)

    with open(os.path.join('catalog_encrypted', filename), 'wb') as file:
        file.write(encrypted_data)


def decrypt(filename, f):
    with open(os.path.join('catalog_encrypted', filename), 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = f.decrypt(encrypted_data)

    with open(os.path.join('catalog_decrypted', filename), 'wb') as file:
        file.write(decrypted_data)


def protectMp3(key):
    f = Fernet(key)
    for filename in os.listdir('server/catalog'):
        encrypt(filename, f)
        decrypt(filename, f)


def encryptPrivKey(key,foldername, filename):
    f = Fernet(key)
    with open(os.path.join(foldername, filename), 'rb') as file:
        file_data = file.read()

    encrypted_data = f.encrypt(file_data)

    with open(os.path.join(foldername,  filename), 'wb') as file:
        file.write(encrypted_data)


##### MAIN #####
# key = "7fPdeSrfCQ2iGrPMCqQ4pesGpproTg26bC9wNjJJE0E=".encode()
# protectMp3(key)


#key_file = 'key_privKserver'
#write_key(key_file)
#key = load_key(key_file)
#encryptPrivKey(key, "server", "Server.pk8")

key_file = 'key_privKclient'
write_key(key_file)
key = load_key(key_file)
encryptPrivKey(key, "client", "clientCert.pk8")
