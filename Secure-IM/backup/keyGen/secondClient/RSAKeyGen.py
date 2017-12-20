#!/usr/bin/python

import os
import sys

try:
	keyType = raw_input("Enter type of key (pem/der): ")

	if keyType == "pem" or keyType == "der":
		pass
	else:
		print "ERROR: Enter appropriate key type!"
		sys.exit()

	keySize = raw_input("Enter Key Size (1024/2048/3072/4096): ")

	if keySize == "1024" or keySize == "2048" or keySize == "3072" or keySize == "4096":
		pass

	else:
		print "ERROR: Enter appropriate key size!"
		sys.exit()

	if keyType == "pem":

		os.system("openssl genrsa -out senderPrivateKey.pem "+keySize)	
		os.system("openssl rsa -in senderPrivateKey.pem -pubout > senderPublicKey.pem")

	 	os.system("openssl genrsa -out destinationPrivateKey.pem "+keySize)
	 	os.system("openssl rsa -in destinationPrivateKey.pem -pubout > destinationPublicKey.pem")

	elif keyType == "der":

		os.system("openssl genrsa -out senderPrivateKey.pem "+keySize)
		os.system("openssl pkcs8 -topk8 -inform PEM -outform DER -in senderPrivateKey.pem -out senderPrivateKey.der -nocrypt")
		os.system("openssl rsa -in senderPrivateKey.pem -pubout -outform DER -out senderPublicKey.der")
		os.system("rm senderPrivateKey.pem")

		os.system("openssl genrsa -out destinationPrivateKey.pem "+keySize)
		os.system("openssl pkcs8 -topk8 -inform PEM -outform DER -in destinationPrivateKey.pem -out destinationPrivateKey.der -nocrypt")
		os.system("openssl rsa -in destinationPrivateKey.pem -pubout -outform DER -out destinationPublicKey.der")
		os.system("rm destinationPrivateKey.pem")

	else:
		sys.exit("ERROR: Key type not supported!")

except KeyboardInterrupt:
	sys.exit("\nFailed to generate keys, try again!")
