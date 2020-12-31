# SIO_projeto2_3
Project from the Subject of Security

## Confidentiality and Integrity (proj 2)
  1. Negotiate a cipher suite between the client and server (at least 2
  ciphers, 2 digests, 2 cipher modes)
  2. Negotiate ephemeral keys between the client and server (valid only for
  a single session)
  3. Encrypt all communications
  4. Validate the integrity of all messages and chunks
  5. Manage cryptographic viewing licenses, based on time or number of
  views
  6. Provide the means for chunk based key rotation
## Authentication and Isolation (proj 3)
7. Mutually authenticate the client and server supported by a custom
  PKI
  8. Authenticate the user viewing the media content
  9. Authenticate the content viewed so that the client can verify the content authenticity
  10. Integrate hardware tokens to authenticate users
  11. Protect the media content at rest in the server
  User registration, media upload, and the PKI required for client/server of
  the content distributor can be done off-line, and should not result in functionality added to the client or server.
  

# Install the following:
 ### For venv:
  apt install virtualenv
  virtualenv -p python3 venv
  bash
  source ./venv/bin/activate
  pip3 install -r client/requirements.txt
  pip3 install -r server/requirements.txt
  
 ### For server:
  pip3 install -U cryptography
  
 ### For client:
  pip3 install twisted
  sudo apt install swig
  pip3 install pyKCS11
