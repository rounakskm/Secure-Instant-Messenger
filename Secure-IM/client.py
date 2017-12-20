#!/usr/bin/python

'''

Author: Soumya Mohanty
	Suraj Bhatia

Title: client.py

Description: Client side program for secure instant chat in Python

Usage: python client.py -u $USERNAME -c keyGen/$UNAMEPublicKey.der keyGen/$UNAMEPrivateKey.der -skey keyGen/serverPublicKey.der -p $PORT 

'''

from socket import *
import argparse
import sys
import select
import sys
import base64
import argparse
import sys
import os
import cPickle
import pickle
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import ast

from fcrypt import *



def prompt():

	sys.stdout.write('+> ')
	sys.stdout.flush()

def serverAuthentication(addr, socket):

	R1 = randint(0, 1000)

	firstMessage = {'message': "LOGIN", 'random': R1, 'user':username}

	cipherLogin = RSAEncryption(serverPubKey, str(firstMessage))

	socket.sendto(cipherLogin, addr)

	try:
		socket.settimeout(4)

		helloMessage = socket.recv(65535)

	except:
		sys.exit("User already in use, please use different name.")

	R1 += 1

	if int(helloMessage.split(" ")[1]) != R1:
		sys.exit("Verification failed!")

	R2 = randint(0, 1000)

	f = open(senderPubKeyFile, 'r')
	publicKeyFile = f.read()
	f.close()	
	

	secondCipherKey = RSAEncryption(serverPubKey, publicKeyFile)
	secondCipherNum = RSAEncryption(serverPubKey, str(R2))

	secondMessage = {"key":secondCipherKey, "random":secondCipherNum}

	secondHash = messageSigning(sendPriKey, str(secondMessage))

	secondMessage['hash'] = secondHash

	socket.sendto(str(secondMessage), addr)

	challenge_dict = socket.recvfrom(65536)
	
	challenge_dict = ast.literal_eval(challenge_dict[0]) #Converting to dict
	
	challenge = RSADecryption(sendPriKey, challenge_dict['challenge'])		
	challenge_R2 = RSADecryption(sendPriKey, challenge_dict['random'])

	# incrementing R2
	R2 = int(R2)+1

	# Check if R2 is incremented
	if not R2 == int(challenge_R2):
		sys.exit("Random number doesnt match") 
	
	auth_status = 'fail'
	while (auth_status == 'fail'):

		try:
			uname = raw_input("Enter username: ")
			# Make password invisible
			password = raw_input("Enter password: ")

		except:
			print "TERMINATE"
			forced_quit = "TERMINATE"
			forced_quit = RSAEncryption(serverPubKey, forced_quit)
			socket.sendto(forced_quit, addr)
			socket.close()
			sys.exit("Forced quit!")			

		# Hashing the password
		pass_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		pass_digest.update(password)
		password = pass_digest.finalize()
		password = base64.b64encode(password)

		# finding answer of the challenge
		challenge_ans = break_hash(challenge)

		# Incrementing the random number
		R2 = int(R2)+1

		# Create DH keys

		dh_private_key, dh_public_key = dh_keygen()

		# Create the message dictionary
		thirdMessage = {"challenge_ans":challenge_ans, "random":R2, "uname" : uname, "password": password, 'dh_key': dh_public_key}

		thirdMessage = cPickle.dumps(thirdMessage)
		# Encrypt the message and sign it then send

		thirdMessage = RSAEncryption(serverPubKey, thirdMessage)
		thirdHash = messageSigning(sendPriKey,thirdMessage)

		# Send challenge_and, uname, password to the server for authentication
		socket.sendto(str(thirdMessage)+"delimiter"+thirdHash, addr)

		# Receive message and see if server auth success or not 
		auth_msg = socket.recvfrom(65536)	

		try:
			auth_msg_dict = auth_msg[0]
			auth_msg_dict = auth_msg_dict.split("delimiter")[0]
			auth_msg_dict = RSADecryption(sendPriKey, auth_msg_dict)
			auth_msg_dict = ast.literal_eval(auth_msg_dict)

			R3 = R2+1
			if not R3 == auth_msg_dict['random']:
				sys.exit("Random number doesnt match")

		except AttributeError:
			auth_msg_dict = RSADecryption(sendPriKey, auth_msg)
			auth_msg_dict = ast.literal_eval(auth_msg)

			R3 = R2+1
			if not R3 == auth_msg_dict['random']:
				sys.exit("Random number doesnt match")

		# Terminate client session after three attempts
		if auth_msg_dict['status'] == 'FAIL':
			print 'Incorrect credentials. Please try again.'
		elif auth_msg_dict['status'] == 'KILL':
			sys.exit('All attempts exhausted. Start new session!!!')
		elif auth_msg_dict['status'] == 'WELCOME':
			print 'o> Authentication Successful'
			auth_status = 'pass'	
		
			# Receive TokenId
			token_id = auth_msg_dict['token_id']

			server_dh_public_key = auth_msg[0].split("delimiter")[1]

			server_shared_key = dh_shared_keygen(dh_private_key, server_dh_public_key)

			return token_id, server_shared_key, dh_private_key, dh_public_key

def c2c_auth(client_addr, dest_pub_key):

	status = 'NOTREGISTERED'
	client_shared_key = None

	dest_pub_key = serialization.load_der_public_key(dest_pub_key, backend=default_backend())

	token_hash = make_hash(token_id)


	f = open(senderPubKeyFile, 'r')
	publicKeyFile = f.read()
	f.close()	

	pk1 = publicKeyFile[0:len(publicKeyFile)/2]

	pk2 = publicKeyFile[len(publicKeyFile)/2:]

	enc_pk1 = RSAEncryption(dest_pub_key, pk1)

	enc_pk2 = RSAEncryption(dest_pub_key, pk2)
	
	# Dict with R1, token_hash and username
	R1 = randint(0,999)
	client_info = {'username':username, 'token_hash':token_hash, 'random':R1}

	enc_client_info = RSAEncryption(dest_pub_key, str(client_info))

	client_auth_msg = {'message':'CLI_AUTH', 'info':enc_client_info, 'pk1':enc_pk1, 'pk2':enc_pk2 }

	client_auth_msg = pickle.dumps(client_auth_msg)

	client_socket.sendto(client_auth_msg, client_addr)
	try:
		DH_message = client_socket.recv(65535)
	except:
		print "<o> Server down, cannot authenticate clients"
		prompt()

	DH_message = pickle.loads(DH_message)

	# Extracting random number from  encrypted DH_message
	random_num =RSADecryption(sendPriKey, DH_message['random'])
	
	# Check if extracted R1 is incremented
	R1 += 1  #Incrementing original R1
	
	if not str(R1) == str(random_num):
			sys.exit("Random number doesnt match")
	
	# Decrypting the DH_public key
	DH_client_pub_key = RSADecryption(sendPriKey, DH_message['key'])

	# Send DH_contribution to client
	CipherKey = RSAEncryption(dest_pub_key, dh_public_key)
	R1 += 1 #increment befor sending
	CipherNum = RSAEncryption(dest_pub_key, str(R1))
	DH_message = {"key":CipherKey, "random":CipherNum}	
	DH_message = pickle.dumps(DH_message)
	client_socket.sendto(DH_message, client_addr) 

	# Generate DH shared key
	client_shared_key = dh_shared_keygen(dh_private_key,DH_client_pub_key)
	
	# Check if shared key was generated and change status 
	if not client_shared_key == None: 
		status = 'REGISTERED'
		return status, client_shared_key
	else:
		return status, client_shared_key



# Function used to bruteforce and find answer of the challenge
def break_hash(challenge_hash):
		
	for num in range(1,1000000):
		challenge_digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    		challenge_digest.update(str(num))
		num_hash = challenge_digest.finalize()
		num_hash = base64.b64encode(num_hash)
		
		if num_hash == challenge_hash:
			return num



def sendToServer(message, socket, username, addr):

	# Retrieve list of users connected to chat from server
	if message == "list":
		try :

			server_iv = os.urandom(16)

			listRequest = {'message':'LIST', 'token':token_id}

			cipher_list, e_tag = AESEncryption(server_shared_key, server_iv, str(listRequest))

			padded_iv = dataPadding(server_iv)

			cipher_list_dict = {'message':cipher_list, 'iv':padded_iv, 'tag':e_tag}

			cipher_list_dict = pickle.dumps(cipher_list_dict)
			
			socket.sendto(cipher_list_dict, addr)

			socket.settimeout(4)

			enc_data, server = socket.recvfrom(65535)

			enc_data = pickle.loads(enc_data)

			logged_list = AESDecryption(server_shared_key, server_iv, enc_data['tag'], enc_data['data'])

			logged_list = ast.literal_eval(logged_list)
			
			print "o> Logged users: "
			for u_name in logged_list:
				if u_name == username:
					continue
				else:
					print "   "+u_name
			#print "\n"

			return logged_list

		except error, msg:
			print "\n <o> Server Down, cannot update list."
			prompt()

def createSocket():

	# Create socket and handle failure
	try:
		clientSocket = socket(AF_INET, SOCK_DGRAM)

	except socket.error:
		print 'Failed to create socket'
		sys.exit(0)

	return clientSocket


parser = argparse.ArgumentParser()

parser.add_argument("-s", "--server",
            default="localhost",
            help="Server IP address or name")

parser.add_argument("-p", "--server-port", type=int,
            default=5569,
            help="port number of server to connect to")

parser.add_argument("-u", "--user",
            default="Alice",
            help="name of user")

parser.add_argument("-c", nargs='+',
	    help="Client Key List",
	    type=str)

parser.add_argument("-skey", nargs='+',
	    help="Server Public Key",
	    type=str)

args = parser.parse_args()

username = args.user

sendPriKey = loadRSAPrivateKey(args.c[1], "der")

senderPubKeyFile = args.c[0]

serverPubKey = loadRSAPublicKey(args.skey[0], "der")

# Retrieve username, server port and IP from command-line

server_addr = (args.server, args.server_port)

# Create client UDP socket
client_socket = createSocket()

server_flag = ''

logged_list = dict()
server_iv  = ''

client_logged_list = dict()

# Send SIGN-IN message to server after socket creation
token_id, server_shared_key, dh_private_key, dh_public_key = serverAuthentication(server_addr, client_socket)

prompt()



try:
	while True:

		# Manage list of different sockets
		socketList = [sys.stdin, client_socket]
		readSocket, writeSocket, errorSocket = select.select(socketList, [], [])

		for sock in readSocket:
			if sock == client_socket:
				# Keep checking for received messages from server or other users
				try:
					data, addr = client_socket.recvfrom(65535)

				except error:
					break

				if not data:
					sys.exit()

				else:

					try:
						data = pickle.loads(data)

												
					except:
						pass

					try:
						data = ast.literal_eval(data)

					except:
						pass

					if data['message'] == 'CHAT':
						chat_message = AESDecryption(client_shared_key, data['chat_iv'], data['chat_tag'], data['chat_message'])

						# Print SEND message
						print "\no> "+data['from']+': '+chat_message
						prompt()						

					if data['message'] == 'CLI_AUTH':
						
						dec_info = RSADecryption(sendPriKey, data['info'])
						dec_pk1 = RSADecryption(sendPriKey, data['pk1'])
						dec_pk2 = RSADecryption(sendPriKey, data['pk2'])
						 
						# Sending tokenid to server for verificaation
						new_iv = os.urandom(16)
						status_info, e_tag = AESEncryption(server_shared_key, new_iv, dec_info)
						token_verify_msg = {'message': 'CHECKTID', 'info':status_info, 'tag': e_tag, 'iv': new_iv}
						token_verify_msg = pickle.dumps(token_verify_msg)
						client_socket.sendto(token_verify_msg, server_addr)
						try:
							result = client_socket.recv(65535)
							
							if result == 'PASS':
								dec_info = ast.literal_eval(dec_info)
								R1 = dec_info['random']
								token_hash = dec_info['token_hash']
								dest_username =  dec_info['username']
								# Recreating the client_public_key of destination
								dest_publicKeyFile = dec_pk1+dec_pk2

								# Start diffie Hellman exchange
								R1 += 1
								dest_publicKeyFile =serialization.load_der_public_key(dest_publicKeyFile,
													 backend=default_backend())
								CipherKey = RSAEncryption(dest_publicKeyFile, dh_public_key)
								CipherNum = RSAEncryption(dest_publicKeyFile, str(R1))
								DH_message = {"key":CipherKey, "random":CipherNum}	
								DH_message = pickle.dumps(DH_message)
								client_socket.sendto(DH_message, addr)
								DH_peer_message = client_socket.recv(65535) 
								DH_peer_message = pickle.loads(DH_peer_message)

								# Extracting random number from  encrypted DH_message
								random_num =RSADecryption(sendPriKey, DH_peer_message['random'])
								 
								# Check if extracted R1 is incremented
								R1 += 1  #Incrementing original R1
								if not str(R1) == str(random_num):
										sys.exit("Random number doesnt match")
	
								# Decrypting the DH_public key
								DH_peer_pub_key = RSADecryption(sendPriKey, DH_peer_message['key'])

								# Generate DH shared key
								client_shared_key = dh_shared_keygen(dh_private_key,DH_peer_pub_key)
							
								# Add shared key to key dict
								client_logged_list[addr] = client_shared_key 
							else:
								print "Failed"
								client_socket.sendto('Wrong token id', addr)

						except:
							print "\n<o> Server down, cannot authenticate clients"
							prompt()

					if data['message'] == 'BYE':

						bye_info = AESDecryption(server_shared_key, data['iv'], data['tag'], data['info'])

						bye_info = ast.literal_eval(bye_info)

						if bye_info['tokenid'] == token_id:
							print "Logging off."
							client_socket.close()
							sys.exit(0)	

					# Exit from chat if server is down
					if data['message'] == "DOWN":
						server_flag = "DOWN"
						try:
							down_info = AESDecryption(server_shared_key, data['iv'], data['tag'], data['info'])
						except:
							continue
	
						if down_info == "Server Down":
							print "\n<o> Server down, continue chatting with listed peers."	
							prompt()

					if data['message'] == "UPDATE":
						try:
							logged_list = AESDecryption(server_shared_key, data['iv'], data['tag'], data['info'])
							logged_list = ast.literal_eval(logged_list)
						except:
							continue	

			else:
				# Take input from user
				user_input = raw_input()

				# Handle user exit
				try:
					if user_input == "exit":

						if server_flag == "DOWN":
							sys.exit("Logging off.")

						exit_iv = os.urandom(16)

						exit_message = {"tokenid": token_id, "username": username}

						cipher_exit, exit_tag = AESEncryption(server_shared_key, exit_iv, str(exit_message))

						cipher_exit_msg = {"message": "LOGOFF",'info':cipher_exit, 'tag': exit_tag, 'iv': exit_iv}

						cipher_exit_msg = pickle.dumps(cipher_exit_msg)

						client_socket.sendto(cipher_exit_msg, server_addr)

					# Blank command goes to next line
					elif user_input =="":
						prompt()

					# Check for message format
					elif user_input.split()[0] == "send":
						try:
							# Extract username and message 
							dest_client = user_input.split()[1]
							input_as_list = user_input.split()
							chat_message = " ".join(input_as_list[2:]) 

							if dest_client in logged_list:
								client_addr = logged_list[dest_client][1]
								dest_pub_key = logged_list[dest_client][0]

							else:
								print "o> "+dest_client+" not logged in! Try refreshing with list."
								prompt()

							try:
								if client_addr not in client_logged_list:

									status, client_shared_key = c2c_auth(client_addr, dest_pub_key)
									# Do status check
									if not status == 'REGISTERED':
										print 'Peer authentication failed. Please try again'
									else:
									
										client_logged_list[client_addr] = client_shared_key 

										# Encrypting the chat
										client_iv = os.urandom(16)							
										enc_chat, c_tag = AESEncryption(client_shared_key, client_iv, chat_message)
										chat_dict = {'message': 'CHAT', 'chat_iv':client_iv, 
											    'chat_tag': c_tag, 'chat_message': enc_chat, 'from':username}
										chat_dict = pickle.dumps(chat_dict)
										client_socket.sendto(chat_dict,
						                                                  client_addr)
										prompt()
								else:
									client_shared_key = client_logged_list[client_addr]
									# Encrypting the chat
									client_iv = os.urandom(16)							
									enc_chat, c_tag = AESEncryption(client_shared_key, client_iv, chat_message)
									chat_dict = {'message': 'CHAT', 'chat_iv':client_iv, 
										    'chat_tag': c_tag, 'chat_message': enc_chat, 'from':username}
									chat_dict = pickle.dumps(chat_dict)
									client_socket.sendto(chat_dict,
					                                                  client_addr)
									prompt()
							
							except NameError:
								pass
						
						except IndexError:
							print "+> Incorrect send format, please try again."
							prompt()					

					# Request from server list of users logged in to chat
					elif user_input == "list":
						logged_list = sendToServer(user_input, client_socket, username, server_addr)
						prompt()

					# Handle invalid chat commands
					else:
						print "+> Command not supported, please try again."
						prompt()

				except:
					client_socket.close()
					sys.exit("\n <o> ERROR, please restart program!")

# Handle keyboard interrup, notify server and exit from chat gracefully
except KeyboardInterrupt:

	c_terminate_iv = os.urandom(16)
	c_terminate_cipher, c_terminate_tag = AESEncryption(server_shared_key, c_terminate_iv, "Client Down")
	c_terminate_message = {'message':'CLIENT DOWN', 'info':c_terminate_cipher, 'tag':c_terminate_tag, 'iv':c_terminate_iv}
	c_terminate_message = pickle.dumps(c_terminate_message)
	client_socket.sendto(c_terminate_message, server_addr)
	client_socket.close()
	sys.exit("\nExit from chat.\n")



