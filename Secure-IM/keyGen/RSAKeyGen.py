#!/usr/bin/python

import os
import sys
import sys

username = sys.argv[1]

publicFileNameDer = username+"PublicKey.der"
privateFileNameDer = username+"PrivateKey.der"

publicFileNamePem = username+"PublicKey.pem"
privateFileNamePem = username+"PrivateKey.pem"

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

		os.system("openssl genrsa -out "+privateFileNamePem+" "+keySize)	
		os.system("openssl rsa -in "+privateFileNamePem+" -pubout > "+publicFileNamePem)

	 	#os.system("openssl genrsa -out destinationPrivateKey.pem "+keySize)
	 	#os.system("openssl rsa -in destinationPrivateKey.pem -pubout > destinationPublicKey.pem")

	elif keyType == "der":

		os.system("openssl genrsa -out "+privateFileNamePem+" "+keySize)
		os.system("openssl pkcs8 -topk8 -inform PEM -outform DER -in "+privateFileNamePem+" -out "+privateFileNameDer+" -nocrypt")
		os.system("openssl rsa -in "+privateFileNamePem+" -pubout -outform DER -out "+publicFileNameDer)
		os.system("rm "+privateFileNamePem)

		#os.system("openssl genrsa -out "+destinationPrivateKey.pem+" "+keySize)
		#os.system("openssl pkcs8 -topk8 -inform PEM -outform DER -in "+destinationPrivateKey.pem+" -out "+destinationPrivateKey.der+" -nocrypt")
		#os.system("openssl rsa -in "+destinationPrivateKey.pem+" -pubout -outform DER -out "+destinationPublicKey.der)
		#os.system("rm "+destinationPrivateKey.pem)

	else:
		sys.exit("ERROR: Key type not supported!")

except KeyboardInterrupt:
	sys.exit("\nFailed to generate keys, try again!")
