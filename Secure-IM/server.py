#!/usr/bin/python

'''

Author: Soumya Mohanty
	Suraj Bhatia

Title: server.py

Description: Server side program for secure instant chat in Python

Usage: python server.py -s keyGen/serverPublicKey.der keyGen/serverPrivateKey.der -p $PORT

'''

from socket import *
import argparse
import sys
import time
import base64
import argparse
import sys
import os
import cPickle
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import random
import ast
from cryptography.hazmat.primitives import serialization

from fcrypt import *

def clientAuthentication(socket, addr, R1):

	#Increment received R1
	R1 = int(R1) + 1

	socket.sendto("HELLO "+str(R1), addr)

	secondMessage = socket.recv(65536)

	#converting str to dict
	secondMessage = ast.literal_eval(secondMessage)
	
	client_pub_key_encrypted = secondMessage['key']
	R2_encrypted = secondMessage['random']
	msg_sign = secondMessage['hash']

	del secondMessage['hash']

	msg_dict_verify = secondMessage
	
	#Decrypting and loading the client_pub_key
	client_pub_key_file = RSADecryption(serverPriKey, client_pub_key_encrypted)	
	client_pub_key = serialization.load_der_public_key(client_pub_key_file, backend=default_backend())
	
	#use client pub key to verify the signature
	if not messageVerification(client_pub_key,str(msg_dict_verify),msg_sign):
		sys.exit("Signature verification failed! Messege not from clint")
	
	#Decrypting R2 and incrementing it
	R2 = RSADecryption(serverPriKey, R2_encrypted)
	
	R2 = int(R2)+1
	
	#send challenge
	challenge_num = random.randint(10000,99999) #generate random 5 digit number	
	challenge = make_hash(challenge_num)

	
	
	#Encrypting the challenge
	challenge_cipher = RSAEncryption(client_pub_key, challenge)
	challenge_random = RSAEncryption(client_pub_key, str(R2))

	challenge_dict = {'challenge': challenge_cipher, 'random': challenge_random}
	
	socket.sendto(str(challenge_dict), addr)


	attempt_count = 0
	auth_flag = False
	while (attempt_count != 3) and (not auth_flag):
		#verify challenge answer, password
		thirdMessage = socket.recvfrom(65536)
		
		try:
			if RSADecryption(serverPriKey, thirdMessage[0]) == 'TERMINATE':
				print "Terminating connection."
				return

		except ValueError:
			pass
	
		thirdMessage = thirdMessage[0].split("delimiter")		
		
		#Check the signature  
		#use client pub key to verify the signature
		if not messageVerification(client_pub_key,thirdMessage[0],thirdMessage[1]):
			sys.exit("Signature verification failed! Messege not from clint")
	
		#Decrypting the messege to retrieve the challenge answer, uname, password
		thirdMessage_dict = RSADecryption(serverPriKey, thirdMessage[0])	


		challenge_msg_dict = cPickle.loads(thirdMessage_dict)

		# challenge_msg_dict = ast.literal_eval(thirdMessage_dict)
	
		challenge_ans =  challenge_msg_dict['challenge_ans']
		uname = challenge_msg_dict['uname']
		password = challenge_msg_dict['password']
		random_num = challenge_msg_dict['random']
		client_dh_key = challenge_msg_dict['dh_key']
	
		#Increment and Check random number
		R2 = R2+1
		
		if not R2 == random_num:
			sys.exit("Random number doesnt match")
	
		#Username, Password authentication
 
		if not password_authenticate(uname, password):
			if attempt_count < 2:			
				attempt_count += 1	
				R3 = R2 + 1	
				auth_msg = {'status': 'FAIL', 'random':R3}	
				auth_msg = RSAEncryption(client_pub_key, str(auth_msg))
				socket.sendto(auth_msg, addr)
			elif attempt_count == 2:
				attempt_count += 1
				R3 = R2 + 1
				kill_msg = {'status': 'KILL', 'random':R3}
				kill_msg = RSAEncryption(client_pub_key, str(kill_msg))

				socket.sendto(kill_msg, addr)	 		
		else:
			dh_private_key, dh_public_key = dh_keygen()
			R3 = R2 + 1

			#Generating token id 
			token_id = str(addr) + ':' + str(challenge_ans)
			token_msg = {'status': 'WELCOME', 'random': R3, 'token_id' : token_id}

			token_msg = RSAEncryption(client_pub_key, str(token_msg))
			socket.sendto(token_msg+"delimiter"+dh_public_key, addr)

			# Computing D-H shared key
			shared_key = dh_shared_keygen(dh_private_key, client_dh_key)
			#addming uname used for login to list 
			uname_in_use.append(uname)
			#Set auth flag to true
			auth_flag = True

	#Kill connection if all authentication attempts exhausted 	
	if not auth_flag:
		#returning status and token_id
		return 'LOGIN FAIL', None, None, None, None   #Send None as token_id, if login fails 	
	else:
		return 'LOGIN SUCCESS', token_id, client_pub_key_file, shared_key, uname



#Function to authenticate the username and password from the serverConf file
def password_authenticate(uname, password):
	if uname in uname_in_use:
		return False
	else:
		for line in open("serverConf.conf","r").readlines(): # Read the lines
			login_info = line.split(':') # Split on the space, and store the results in a list of two strings
			if uname == login_info[0] and password == login_info[1][:-1]:
				print 'Authentication Sucessfull.'                
				return True
		print 'Incorrect credentials.'
		return False

		




def createSocket(serverPort):

	# Create Server socket
	try:
		serverSocket = socket(AF_INET, SOCK_DGRAM)

	# Socket create error handle
	except error, createError:
		print "Failed to create socket. Error: "+str(creatError)
		sys.exit(0)

	# Bind socket to all its interfaces and the specified port number
	try:
		serverSocket.bind(('', serverPort))
		print("Server Initialized...")

	# Socket create error handle
	except error, bindError:
		print "Failed to bind socket. Error: "+str(bindError)
		sys.exit(0)

	return serverSocket



parser = argparse.ArgumentParser()

parser.add_argument("-p", "--server-port", type=int,
            default=5569,
            help="port number of server to connect to")

parser.add_argument("-s", nargs='+',
	    help="Server Key List",
	    type=str)

args = parser.parse_args()

serverPubKey = loadRSAPublicKey(args.s[0], "der")
serverPriKey = loadRSAPrivateKey(args.s[1], "der")



# Create server socket
serverSocket = createSocket(args.server_port)

# Maintain dictionary mapping of username and addresses
logged_users = dict()
logged_list = dict()
uname_in_use=[]
username_list = []


try:
	while True:
		print 'Server Listening ...'
		# Wait for messages to be received infinitely. handle accordingly
		message, addr = serverSocket.recvfrom(65535)
		try:
			message = RSADecryption(serverPriKey, message)

		except:
			pass

	
		try:
			message = pickle.loads(message)
		except KeyError:
			pass

		except IndexError:
			pass

		try:
			message = ast.literal_eval(message)
		except ValueError:
			pass
		except SyntaxError:
			pass

		try:

			padded_iv = message['iv']

			iv = dataUnpadding(padded_iv)

			tag = message['tag']

			if addr in logged_users:
				shared_key = logged_users[addr][-1]

				message = AESDecryption(shared_key, iv, tag, message['message'])
		except:
			pass

		try:
			message = ast.literal_eval(message)
		except ValueError:
			pass
		except SyntaxError:
			pass

		if message['message'] == "LOGIN":

			username = message['user']

			if username in username_list:
				print "Username already in use."
			else: 
				try:	
					login_status, token_id, client_pub_key_file, shared_key, u_name = clientAuthentication(serverSocket, addr, message['random'])
			                                                            

					if login_status == 'LOGIN FAIL':
						continue

					elif login_status == 'LOGIN SUCCESS':
						# Add to logged users dictionary

						logged_users[addr] = [username, u_name, client_pub_key_file, token_id, shared_key]

						logged_list[username] =  [client_pub_key_file, addr]
			
						print ("Registering %s" % (username))

						#Add -u username to the list
						for key in logged_users:
							if logged_users[key][0] not in username_list: 
								username_list.append(logged_users[key][0])

						
				except TypeError:
					pass

		if message['message'] == "LIST":

			if addr in logged_users:
				shared_key = logged_users[addr][-1]
				cipher_list, tag = AESEncryption(shared_key, iv, str(logged_list))
				cipher_list_reply = {'message':'LISTREP', 'tag':tag, 'data':cipher_list}
				cipher_list_reply = pickle.dumps(cipher_list_reply)			
				serverSocket.sendto(cipher_list_reply, addr)

			else:
				serverSocket.sendto("First Authenticate with server", addr)
		if message['message'] == "CHECKTID":
			if addr in logged_users:
				shared_key = logged_users[addr][-1]
						
			status_info = AESDecryption(shared_key, message['iv'], message['tag'], message['info'])
			
			#Retreiving the tokenid of the user received
			if addr in logged_users:
				client_token_id = logged_users[addr][-2]
			#Creating the hash of the tokenid
			client_token_id_hash = make_hash(client_token_id)
			
			#Comparing the hashes
			status_info = ast.literal_eval(status_info)
			if client_token_id_hash == status_info['token_hash']:
				serverSocket.sendto('PASS', addr)
			else: 
				serverSocket.sendto('PASS', addr)

		if message['message'] == "LOGOFF":
			if addr in logged_users:
				#Remove uname form uname_in_use
				u_name = logged_users[addr][1]
				uname_in_use.remove(u_name)
				username_list.remove(logged_users[addr][0])
				exit_shared_key = logged_users[addr][-1]
				
				logoff_info = AESDecryption(exit_shared_key, message['iv'], message['tag'], message['info'])
				logoff_info = ast.literal_eval(logoff_info)

				bye_info = {'tokenid':logoff_info['tokenid']}
				bye_iv = os.urandom(16)
				bye_cipher, bye_tag = AESEncryption(exit_shared_key, bye_iv, str(bye_info))
				bye_message = {'message':'BYE', 'info':bye_cipher, 'tag':bye_tag, 'iv':bye_iv}
				bye_message = pickle.dumps(bye_message)
				serverSocket.sendto(bye_message, addr)

				del logged_users[addr]
				del logged_list[logoff_info['username']]

				print logoff_info['username']+" has logged off"

				for addr in logged_users:
		
					update_iv = os.urandom(16)
					update_cipher, update_tag = AESEncryption(logged_users[addr][-1], update_iv, str(logged_list))
					update_message = {'message':'UPDATE', 'info':update_cipher, 'tag':update_tag, 'iv':update_iv}
					update_message = pickle.dumps(update_message)
					serverSocket.sendto(update_message, addr)

		if message['message'] == "CLIENT DOWN":
						
				try:
					down_info = AESDecryption(logged_users[addr][-1], message['iv'], message['tag'], message['info'])
				except:
					continue

				if down_info == "Client Down":
					print logged_users[addr][0]+" has logged off"

					uname_in_use.remove(logged_users[addr][1])
					username_list.remove(logged_users[addr][0])
					del logged_list[logged_users[addr][0]]
					del logged_users[addr]

				for addr in logged_users:
		
					update_iv = os.urandom(16)
					update_cipher, update_tag = AESEncryption(logged_users[addr][-1], update_iv, str(logged_list))
					update_message = {'message':'UPDATE', 'info':update_cipher, 'tag':update_tag, 'iv':update_iv}
					update_message = pickle.dumps(update_message)
					serverSocket.sendto(update_message, addr)
					

	serverSocket.close()

# Handle keyboard interrupt and inform connected clients of break down
except KeyboardInterrupt:
	for addr in logged_users:
		
		terminate_iv = os.urandom(16)
		terminate_cipher, terminate_tag = AESEncryption(logged_users[addr][-1], terminate_iv, "Server Down")
		terminate_message = {'message':'DOWN', 'info':terminate_cipher, 'tag':terminate_tag, 'iv':terminate_iv}
		terminate_message = pickle.dumps(terminate_message)
		serverSocket.sendto(terminate_message, addr)

	serverSocket.close()
	
	

