# -*- coding: utf-8 -*-
#!/usr/bin/python


# Cryptography modules
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dh, ec
from cryptography.hazmat.primitives import padding as paddingFunction



# Python modules
from socket import *
import argparse
import sys
import os
import base64

def AESEncryption(key, iv, pt):

	cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())

	encryptor = cipher.encryptor()

	ct = encryptor.update(pt) + encryptor.finalize()

	return ct, encryptor.tag

def AESDecryption(key, iv, tag, ct):

	cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())

	decryptor = cipher.decryptor()

	pt = decryptor.update(ct) + decryptor.finalize()

	return pt

def HASHFunction(data, key):
	
	# Hashing the message for integrity check

	h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())

	h.update(data)

	messageDigest = h.finalize()

	return messageDigest

def RSAEncryption(destPubKey, key):

	cipherKey = destPubKey.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),algorithm=hashes.SHA256(),label=None))

	return cipherKey

def RSADecryption(destPriKey, cipherKey):

	key = destPriKey.decrypt(cipherKey,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA512()),algorithm = hashes.SHA256(),label = None))

	return key

def dataPadding(data):
	
	# Padding data using PKCS7 to 128-bits

	padder = paddingFunction.PKCS7(128).padder()

	paddedData = padder.update(data)

	paddedData += padder.finalize()

	return paddedData

def dataUnpadding(paddedData):
	
	# Unpadding data

	unpadder = paddingFunction.PKCS7(128).unpadder()

	data = unpadder.update(paddedData)

	data += unpadder.finalize()

	return data

def messageSigning(sendPriKey, message):
	
	# Function for signing the message to be verified at the destination

	signer = sendPriKey.signer(padding.PSS(mgf = padding.MGF1(hashes.SHA512()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA512())

	signer.update(message)

	signature =  signer.finalize()

	return signature

def messageVerification(sendPubKey, message, signature):
	
	# Function for verifying the signed message that was sent

	verifier = sendPubKey.verifier(signature,padding.PSS(mgf = padding.MGF1(hashes.SHA512()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA512())

	verifier.update(message)

	try:
		verifier.verify()
		return True

	except:
		return False

def loadRSAPublicKey(publicKeyFile, keyType):
	
	# Function for opening the public key files, reading the content and serializing it
	try:
		with open(publicKeyFile, "rb") as keyFile:

			if keyType == 'der':
				try:
					publicKey = serialization.load_der_public_key(keyFile.read(), backend=default_backend())
				except ValueError:
					sys.exit("ValueError: Could not deserialize key data, please check key file for modifications")
				
			elif keyType == 'pem':
				try:
					publicKey = serialization.load_pem_public_key(keyFile.read(), backend=default_backend())
				except ValueError:
					sys.exit("ValueError: Could not deserialize key data, please check key file for modifications")
			else:
				sys.exit("ERROR: Unknown key type.")
	except IOError:
		sys.exit("ERROR: No such public key file, verify arguments again!")
		
	return publicKey

def loadRSAPrivateKey(privateKeyFile, keyType):
	
	# Function for opening the private key files, reading the content and serializing it
	try:
		with open(privateKeyFile, "rb") as keyFile:

			if keyType == 'der':
				try:
					privateKey = serialization.load_der_private_key(keyFile.read(),password = None,backend = default_backend())
				except ValueError:
					sys.exit("ValueError: Could not deserialize key data, please check key file for modifications")

			elif keyType == "pem":
				try:
					privateKey = serialization.load_pem_private_key(keyFile.read(),password = None,backend = default_backend())
				except ValueError:
					sys.exit("ValueError: Could not deserialize key data, please check key file for modifications")
			else:
				sys.exit("ERROR: Unknown key type.")
	except IOError:
		sys.exit("ERROR: No such private key file, verify arguments again!")
		
	return privateKey
'''
def dh_keygen():

	parameters = dh.generate_parameters(generator=2, key_size=512,
                                     backend=default_backend())

	private_key = parameters.generate_private_key()
	
	public_key = private_key.public_key()

	public_key = base64.b64encode(public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo))

	return private_key, public_key

def dh_shared_keygen(my_private_key, their_public_key):

	their_public_key = base64.b64decode(their_public_key)

	their_public_key = serialization.load_der_public_key(data=their_public_key, backend=default_backend())

	shared_key = my_private_key.exchange(their_public_key)

	salt = os.urandom(16)

	kdf = PBKDF2HMAC(
	algorithm=hashes.SHA256(),
        length=32,
	salt=salt,
        iterations=100000,
	backend=default_backend()
	)

	key = kdf.derive(shared_key)

	# print 'FINAL: '+base64.b64encode(key)

	return key

'''

def dh_keygen():

	private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
	
	public_key = private_key.public_key()

	public_key = base64.b64encode(public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo))

	return private_key, public_key

def dh_shared_keygen(my_private_key, their_public_key):

	their_public_key = base64.b64decode(their_public_key)

	their_public_key = serialization.load_der_public_key(data=their_public_key, backend=default_backend())

	shared_key = my_private_key.exchange(ec.ECDH(), their_public_key)

	# salt = os.urandom(16)

	salt = b'69685906859068590658'

	kdf = PBKDF2HMAC(
	algorithm=hashes.SHA256(),
        length=32,
	salt=salt,
        iterations=100000,
	backend=default_backend()
	)

	key = kdf.derive(shared_key)

	return key

def make_hash(data):

	data_digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    	data_digest.update(str(data))
    	data_hash = data_digest.finalize()
    	data_hash = base64.b64encode(data_hash)

	return data_hash








