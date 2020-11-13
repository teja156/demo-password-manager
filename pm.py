import os.path
from os import path
import sqlite3

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
import hashlib
import aes
import ast

def createDB():
	if(path.exists("passwords.db")):
		return
	conn = sqlite3.connect('passwords.db')
	conn.execute('''CREATE TABLE passwords(id INTEGER PRIMARY KEY, site_url TEXT, username text, password text)''')
	conn.commit()
	conn.close()
	print("Created Database")



def addPassword():
	createDB()
	site_url = input("Enter website URL : ")
	username = input("Enter username : ")
	password = input("Enter password : ")

	#encrypt with public key
	f = open("pubkey.pem","r")
	pubkey = RSA.import_key(f.read())
	f.close()
	encryptor = PKCS1_OAEP.new(pubkey)
	encrypted = encryptor.encrypt(password.encode('utf-8'))
	print(type(encrypted))
	# print("Encrypted : ",encrypted)
	# print("Encrypted: ", binascii.hexlify(encrypted))
	conn = sqlite3.connect('passwords.db')

	c=conn.cursor()

	# Insert a row of data
	data = (site_url,username,binascii.hexlify(encrypted))
	c.execute('INSERT INTO passwords(site_url, username, password) VALUES (?,?,?)', data)

	conn.commit()
	conn.close()

	print("Password added")


def viewPasswords():
	conn = sqlite3.connect('passwords.db')
	c=conn.cursor()
	for row in c.execute('SELECT * FROM passwords'):
		print(row)

	inp = int(input("Enter option : "))
	cur = conn.cursor()
	cur.execute("SELECT password FROM passwords WHERE id=?", (inp,))

	rows = cur.fetchall()
	encryptedPass = rows[0][0]
	# print("encryptedPass in bytes: ",encryptedPass.decode('ascii'))
	conn.close()
	mp = input("Enter master password : ")
	sk = open("sk.txt","r").read()
	tk = mp + sk

	salt = open('salt.bin','rb').read()

	# print("Using salt : ",salt)

	muk = hashlib.pbkdf2_hmac(
	    'sha256', # The hash digest algorithm for HMAC
	    mp.encode('utf-8'), # Convert the password to bytes
	    salt, # Provide the salt
	    100000, # It is recommended to use at least 100,000 iterations of SHA-256 
	    dklen=32 # Get a 256 bits key
	)


	# print("MUK : ",muk)

	

	#decrypt private key
	f = open("encryptedPrivateKey","r")
	encryptedPrivateKey = ast.literal_eval(f.read())
	f.close()

	try:
		decrypted = aes.decrypt_AES_GCM(encryptedPrivateKey,muk)
		privatekey = RSA.import_key(decrypted)
		# print("decrypted private key", decrypted.decode('ascii'))
		encryptedPass = bytes.fromhex(encryptedPass.decode('utf-8'))
		#decrypt data with private key now

		cipher_rsa = PKCS1_OAEP.new(privatekey)
		decryptedPassword = cipher_rsa.decrypt(encryptedPass)

		print("Password : ",decryptedPassword.decode('utf-8'))
	except:
		print("Wrong MASTER PASSWORD")


while True:
	inp = int(input("1. Add a Password\n2. View Passwords\nEnter option : "))
	if(inp==1):
		addPassword()
	if(inp==2):
		viewPasswords()
