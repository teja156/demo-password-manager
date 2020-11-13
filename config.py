import uuid
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
from Crypto.Cipher import AES
import aes
import ast

mp = input("Choose your your master password : ")

#generate secret key and write to file
sk = uuid.uuid1()
f=open("sk.txt","w")
f.write(str(sk))
f.close()

#append both
tk = mp + str(sk)

#pbkdf2
salt = os.urandom(16)
print("salt generated : ",salt)
f = open('salt.bin','wb')
f.write(salt)
f.close()

muk = hashlib.pbkdf2_hmac(
    'sha256', # The hash digest algorithm for HMAC
    mp.encode('utf-8'), # Convert the password to bytes
    salt, # Provide the salt
    100000, # It is recommended to use at least 100,000 iterations of SHA-256 
    dklen=32 # Get a 256 bits key
)

print("Derived Master Unlock Key (MUK) : ",muk)
# f = open("muk","wb")
# f.write(muk)
# f.close()
print("\n\n")



keyPair = RSA.generate(3072)
pubKey = keyPair.publickey()
pubKeyPEM = pubKey.exportKey()
f = open('pubkey.pem','w')
f.write(pubKeyPEM.decode('ascii'))
f.close()
privKeyPEM = keyPair.exportKey()
# print("Generated Private Key : ",privKeyPEM.decode('ascii'))
#encrypt privatekey with MUK
encryptedPrivateKey = aes.encrypt_AES_GCM(msg=privKeyPEM,secretKey=muk)
print("encryptedPrivateKey", {
    'ciphertext': binascii.hexlify(encryptedPrivateKey[0]),
    'aesIV': binascii.hexlify(encryptedPrivateKey[1]),
    'authTag': binascii.hexlify(encryptedPrivateKey[2])
})

f = open("encryptedPrivateKey","w")
f.write(str(encryptedPrivateKey))
f.close()


# f = open("encryptedPrivateKey","r")
# encryptedPrivateKey = ast.literal_eval(f.read())
# f.close()
# decrypted = aes.decrypt_AES_GCM(encryptedPrivateKey,muk)
# print("decrypted private key", decrypted.decode('ascii'))












