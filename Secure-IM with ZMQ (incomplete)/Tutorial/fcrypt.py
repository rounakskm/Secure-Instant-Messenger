# -*- coding: utf-8 -*-
#!/usr/bin/python

'''

Author: Suraj Bhatia

Title: fcrypt.py

Description: Python application that can be used to encrypt and sign a file to be sent by email.

Usage: python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file

       python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file

'''

# Cryptography modules
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import padding as paddingFunction

# Python modules
from socket import *
import argparse
import sys
import os
import base64

def AESEncryption(key, associatedData, iv, pt):

	cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())

	encryptor = cipher.encryptor()

	encryptor.authenticate_additional_data(associatedData)

	ct = encryptor.update(pt) + encryptor.finalize()

	return ct, encryptor.tag

def AESDecryption(key, associatedData, iv, tag, ct):

	cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())

	decryptor = cipher.decryptor()

	decryptor.authenticate_additional_data(associatedData)

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

def argsParser():

	# Command-line arguments parser
	parser = argparse.ArgumentParser()

	parser.add_argument("-e", nargs='+', help="Encryption Parameter List", type=str)
	parser.add_argument("-d", nargs='+', help="Decryption Parameter List", type=str)

	args = parser.parse_args()

	if args.e:

		if args.e != 'None' and len(args.e) == 4:
			return args.e, "e"
		else:
			print "ERROR: Four paramaters required, try again."
			sys.exit()

	elif args.d:
		if args.d != 'None' and len(args.d) == 4:
			return args.d, "d"
		else:
			print "ERROR: Four paramaters required, try again."
			sys.exit()

def Encryption(paramList, operation, firstName, lastName, associatedData):

	# Find out type of RSA keys generated
	keyType = os.path.splitext(paramList[0])[1].split('.')[1]
	
	# Check for PEM and DER keys only
	if keyType == 'pem' or keyType == 'der':
		pass
	else:
		sys.exit("ERROR: Unsupported key file type, please try again!")

	# Parse command-line arguments
	destPubKey = loadRSAPublicKey(paramList[0], keyType)
	sendPriKey = loadRSAPrivateKey(paramList[1], keyType)
	ptFile = paramList[2]
	ctFile = paramList[3]

	# Create random 256-bit AES key and 128-bit Initialization Vector
	key = os.urandom(32)
	iv = os.urandom(16)

	# Read data from input plaintext file to be encrypted
	try:
		pt = open(ptFile, "rb").read()
	except IOError:
		sys.exit("ERROR: No such file/directory, verify arguments again!")

	# Open output file where encrypted data will be stored and sent
	try:
		outputFile = open(ctFile, "wb")
	except IOError:
		sys.exit("ERROR: No such file/directory, verify arguments again!")
		
	# Generate cipher text and tag data from AES	
	ct, tag = AESEncryption(key, associatedData, iv, pt)

	# Add ciphertext and identifier in output file
	outputFile.write(ct)
	outputFile.write(firstName)

	# Encrypt AES key using RSA Encryption using destination's public key
	cipherKey = RSAEncryption(destPubKey, key)

	# Padd the IV
	paddedIV = dataPadding(iv)

	# Add encrypted key, padded IV and second identifer to output file
	outputFile.write(cipherKey+paddedIV)
	outputFile.write(lastName)

	# Hash the cipher text and encrypted key using the AES symmetric key
	messageDigest = HASHFunction(ct+cipherKey, key)

	# Add hashed message and first identifer to output file
	outputFile.write(messageDigest +base64.b64encode(str(len(cipherKey))))
	outputFile.write(firstName)

	# Create a message with all information to be signed
	fullMessage = ct + cipherKey + paddedIV + messageDigest
	signedMessage = messageSigning(sendPriKey, fullMessage)

	# Add signed message, second identifer and tag data to output file
	outputFile.write(signedMessage)
	outputFile.write(lastName)
	outputFile.write(tag)
	outputFile.close()

def Decryption(paramList, operation, firstName, lastName, associatedData):

	# Find out type of RSA keys generated
	keyType = os.path.splitext(paramList[0])[1].split('.')[1]
	
	# Check for PEM and DER keys only
	if keyType == 'pem' or keyType == 'der':
		pass
	else:
		sys.exit("ERROR: Unsupported key file type, please try again!")

	# Parse command-line arguments
	destPriKey = loadRSAPrivateKey(paramList[0], keyType)
	sendPubKey = loadRSAPublicKey(paramList[1], keyType)
	ctFile = paramList[2]
	ptFile = paramList[3]

	# Open output file where decrypted data will be stored
	try:
		output = open(ctFile, 'rb').read()
	except IOError:
		sys.exit("ERROR: No such file/directory, verify arguments again!")
		
	# Using first identifier, split the encrypted message
	try:
		ct, cipherKey_paddedIV_messageDigest_cipherKeyLength, signedMessage_tag = output.split(firstName)
	except ValueError:
		sys.exit("ERROR: Decryption failed!")
		
	# Using second identifier, split one part
	try:
		cipherKey_paddedIV, messageDigest_cipherKeyLength = cipherKey_paddedIV_messageDigest_cipherKeyLength.split(lastName)
	except ValueError:
		sys.exit("ERROR: Decryption failed!")
		
	# Get the hashed message of size 512-bits
	messageDigest = messageDigest_cipherKeyLength[0:64]
	
	# Get length of encrypted key and from that the key and padded IV
	cipherKeyLength = base64.b64decode(messageDigest_cipherKeyLength[64:])
	cipherKey = cipherKey_paddedIV[0:int(cipherKeyLength)]
	paddedIV = cipherKey_paddedIV[int(cipherKeyLength):]

	# Get and verify the signed message
	try:
		signedMessage, tag = signedMessage_tag.split(lastName)
	except ValueError:
		sys.exit("ERROR: Decryption failed!")
		
	fullMessage = ct + cipherKey + paddedIV + messageDigest

	if messageVerification(sendPubKey, fullMessage, signedMessage) == False:
		sys.exit("ERROR: Signature verification failed, try again!")

	# Decrypt the AES key with destination's private key
	key = RSADecryption(destPriKey, cipherKey)

	# Verify the hash created using AES key
	hashVerification = HASHFunction(ct+cipherKey, key)

	if hashVerification != messageDigest:
		sys.exit("ERROR: Hash values do not match.")

	# Unpadd the IV
	iv = dataUnpadding(paddedIV)
	
	# Decrypt using AES the actual data
	try:
		pt = AESDecryption(key, associatedData, iv, tag, ct)
	
	except ValueError:
		sys.exit("ERROR: Invalid key size (512) for AES")
		
	except cryptography.exceptions.InvalidTag:
		sys.exit("ERROR: Invalid tag!")
	
	# Write the decrypted message to the output file	
	outputFile = open(ptFile, "wb")
	outputFile.write(pt)
	outputFile.close()

def main():

	# Create unique identifiers which will help in encryption/decryption process
	firstName = base64.b64decode('z4DPhc+BzrHPgA====') 	# which is = πυραπ  (Suraj in Greek letters)
	lastName = base64.b64decode('zrLOt86xz4TOuc6x==')  	# which is = βηατια (Bhatia in Greek letters)

	# Creating additional data for AES encryption/decryption
	associatedData = firstName+lastName

	# Retrieve parameters for encryption/decryption operation from command-line
	paramList, operation  = argsParser()

	# Depending on upon parameter, execute the corresponding operation
	if operation == 'e':
		Encryption(paramList, operation, firstName, lastName, associatedData)

	elif operation == 'd':
		Decryption(paramList, operation, firstName, lastName, associatedData)

	else:
		sys.exit("Invalid operation parameter, try again.")

if __name__ == "__main__":
    main()

