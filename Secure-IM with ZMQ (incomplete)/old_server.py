#!/usr/bin/env python
#
'''
Simple Chat Program that allows users to register, request the list of registered users,
and send a message to another user through the server. This code can get you started with
your CS4740/6740 project.
Note, that a better implementation would use google protobuf more extensively, with a
single message integrating both control information such as command type and other fields.
See the other provided tutorial on Google Protobuf.
Also, note that the services provided by this sample project do not nessarily satisfy the
functionality requirements of your final instant messaging project.
Finally, we use DEALER and ROUTER to be able to communicate back and forth with multiple
clients (ROUTER remembers identities [first part of message] when it receives a message and
prepends identity to messages when sending to DEALER). See:
  http://zguide.zeromq.org/php:chapter3.
'''

__author__      = "Guevara Noubir"


import zmq
import sys
import time
import base64
import argparse
import sys
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import random
import ast
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, '/home/sbhatia/git/CS-6740/FinalProject/keyGen')
sys.path.insert(0, '/home/sbhatia/git/CS-6740/FinalProject/protobuf')

from fcrypt import AESEncryption
from fcrypt import AESDecryption
from fcrypt import RSAEncryption
from fcrypt import RSADecryption
from fcrypt import messageSigning
from fcrypt import messageVerification
from fcrypt import loadRSAPublicKey
from fcrypt import loadRSAPrivateKey

import messaging_app_pb2


def clientAuthentication(serverPubKey, serverPriKey, ident, R1):

	#Increment received R1
	R1 = int(R1) + 1

	socket.send_multipart([ident, "HELLO "+str(R1)])

	secondMessage = socket.recv_multipart()
	
	#converting str to dict	
	msg_dict = ast.literal_eval(secondMessage[1])	
	
	client_pub_key_encrypted = msg_dict['key']
	R2_encrypted = msg_dict['random']

	#Decrypting and loading the client_pub_key
	client_pub_key = RSADecryption(serverPriKey, client_pub_key_encrypted)	
	client_pub_key = serialization.load_der_public_key(client_pub_key, backend=default_backend())
	
	#use client pub key to verify the signature
	if not messageVerification(client_pub_key,secondMessage[1],secondMessage[2]):
		sys.exit("Signature verification failed! Messege not from clint")
	
	#Decrypting R2 and incrementing it
	R2 = RSADecryption(serverPriKey, R2_encrypted)
	#print 'R2 decrypted: '+str(R2)
	R2 = int(R2)+1
	#print 'incremented R2: '+str(R2)
	#send challenge
	challenge_num = random.randint(10000,99999) #generate random 5 digit number	
	challenge = create_challenge(challenge_num)

	
	
	#Encrypting the challenge
	challenge_cipher = RSAEncryption(client_pub_key, challenge)
	challenge_random = RSAEncryption(client_pub_key, str(R2))
	#print "challenge encryption sucessfull"

	challenge_dict = {'challenge': challenge_cipher, 'random': challenge_random}
	
	socket.send_multipart([ident, str(challenge_dict)])


	attempt_count = 0
	auth_flag = False
	while (attempt_count != 3) and (not auth_flag):
		#verify challenge answer, password
		thirdMessage = socket.recv_multipart()
	
		#Check the signature  
		#use client pub key to verify the signature
		if not messageVerification(client_pub_key,thirdMessage[1],thirdMessage[2]):
			sys.exit("Signature verification failed! Messege not from clint")
		#print 'Signature verification successful'
	
		#Decrypting the messege to retrieve the challenge answer, uname, password
		thirdMessage_dict = RSADecryption(serverPriKey, thirdMessage[1])	
	
		challenge_msg_dict = ast.literal_eval(thirdMessage_dict)
	
		challenge_ans =  challenge_msg_dict['challenge_ans']
		uname = challenge_msg_dict['uname']
		password = challenge_msg_dict['password']
		random_num = challenge_msg_dict['random']
	
		#Increment and Check random number
		R2 = R2+1
		#print R2
		#print random_num
		if not R2 == random_num:
			sys.exit("Random number doesnt match")
	
		#Username, Password authentication
 
		if not password_authenticate(uname, password):
			if attempt_count < 2:			
				attempt_count += 1	
				R3 = R2 + 1	
				auth_msg = {'status': 'FAIL', 'random':R3}	
				auth_msg = RSAEncryption(client_pub_key, str(auth_msg))
				socket.send_multipart([ident, auth_msg])
			elif attempt_count == 2:
				attempt_count += 1
				R3 = R2 + 1
				kill_msg = {'status': 'KILL', 'random':R3}
				kill_msg = RSAEncryption(client_pub_key, str(kill_msg))
				socket.send_multipart([ident, kill_msg])	 		
		else:
			R3 = R2 + 1
			#Generating token id 
			token_id = ident + ':' + str(challenge_ans)
			token_msg = {'status': 'WELCOME', 'random': R3, 'token_id' : token_id}
			token_msg = RSAEncryption(client_pub_key, str(token_msg))
			socket.send_multipart([ident, token_msg])			
			auth_flag = True

	#Kill connection if all authentication attempts exhausted 	
	if not auth_flag:
		#returning status and token_id
		return 'LOGIN FAIL', None   #Send None as token_id, if login fails 	
	else:
		return 'LOGIN SUCCESS', token_id, client_pub_key
	
	

#Function to send the challenge to the client
def create_challenge(challenge_num):    

    #hash the random number created above
    challenge_digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    challenge_digest.update(str(challenge_num))
    challenge_hash = challenge_digest.finalize()
    challenge_hash = base64.b64encode(challenge_hash)

    return challenge_hash



#Function to authenticate the username and password from the serverConf file
def password_authenticate(uname, password):
	for line in open("serverConf.conf","r").readlines(): # Read the lines
		login_info = line.split(':') # Split on the space, and store the results in a list of two strings
		if uname == login_info[0] and password == login_info[1][:-1]:
			print 'Authentication Sucessfull!!!'                
			return True
	print 'Incorrect credentials.'
	return False

		

parser = argparse.ArgumentParser()

parser.add_argument("-p", "--server-port", type=int,
                    default=5569,
                    help="port number of server to connect to")

parser.add_argument("-s", nargs='+',
		    help="Server Key List",
		    type=str)

args = parser.parse_args()

serverPubKey = loadRSAPublicKey(args.s[0], "pem")
serverPriKey = loadRSAPrivateKey(args.s[1], "pem")

#  Prepare our context and sockets
context = zmq.Context()

# We are using the DEALER - ROUTER pattern see ZMQ docs
socket = context.socket(zmq.ROUTER)
socket.bind("tcp://*:%s" %(args.server_port))

# store registered users in a dictionary
logged_users = dict()
logged_ident = dict()
token_id_dict = dict()
logged_users_keys = dict()

# clientAuthentication(serverPubKey, serverPriKey)

# status, token_id, client_pub_key = clientAuthentication(serverPubKey, serverPriKey, ident, message['random']) #passing R1

# main loop waiting for users messages
while(True):

	print "Server Listening"
	original_message = socket.recv_multipart()
	#print "ORIGINAL MESSAGE: "+str(original_message)
	if len(original_message) == 4:
		username = original_message[2]

	# Remeber that when a ROUTER receives a message the first part is an identifier
	# to keep track of who sent the message and be able to send back messages
	ident = original_message[0]
	print ident
	
	try:
		message = RSADecryption(serverPriKey, original_message[1])
		#print message
	except ValueError:
		continue
	try:
		message = ast.literal_eval(message)
	except ValueError:
		continue
	
	print "THE MESSAGE IS: "+str(message)

	# print type(message)
	# print len(message)
	
	if len(message) == 2 and message['message'] == 'LOGIN':
		#print message['message'] 	
		#Initial Login sequence	
		print 'Initiating authentication'	
		status, token_id, client_pub_key = clientAuthentication(serverPubKey, serverPriKey, ident, message['random']) #passing R1
		if status == 'LOGIN FAIL':
			continue
		elif status == 'LOGIN SUCCESS':
			# Add to logged users dictionary
			# Add ident to logged ident dictionary

			logged_users[username] = ident
			logged_users_keys[username] = client_pub_key
			print logged_users_keys
			logged_ident[ident] = username
			user = messaging_app_pb2.User()
			user.ParseFromString(original_message[3])
			print ("Registering %s" % (user.name))
			
			 
			token_id_dict[username] = token_id
			
			# print 'logged_users:'
			# print logged_users
			# print 'logged_ident:'
			# print logged_ident
			# print 'token_id_dict:'
			# print token_id_dict

			# registerMessage = RSAEncryption(client_pub_key, str([ident, b"REGISTER", b'Welcome %s!' %(str(user.name))]))

			# print "\n\n"+str(registerMessage)

			# socket.send_multipart([ident, b'REGISTER', base64.b64encode(str(registerMessage))])

			#print "IM SENDING REGISTER"

			socket.send_multipart([ident, b"REGISTER", b'Welcome %s!' %(str(user.name))])

	elif len(message) == 3 and message['message'] == "LOGOFF":
		#print "I AM LOGGING OFF users"
		
		bye_message = {'message':'BYE', 'tokenid':message['tokenid']}

		bye_cipher = RSAEncryption(logged_users_keys[username], str(bye_message))

		socket.send_multipart([ident, b'BYE', base64.b64encode(str(bye_cipher))])

		del logged_users[username]
		del logged_users_keys[username]
		
		print username+" has logged off"

		#ident?
			
	elif len(message) == 2 and message['message']== 'LIST':
		# If first seeing this identity sent back ERR message requesting a REGISTER		
		if ident not in logged_ident:
			socket.send_multipart([ident, b'ERR', b'You need to register first.'])
		else:
			print("List request from user %s" %(logged_ident[ident]))

			listReply = RSAEncryption(logged_users_keys[username], str(logged_users))

			socket.send_multipart([ident, b'LIST', base64.b64encode(str(listReply))])


	if len(message) == 4:
		if message[1] == 'SEND':
			# check if destination is registered, retrieve address, and forward
			if message[2] in logged_users:
				print "sending message to %s" %(message[2])

			# Note that message from ROUTER is prepended by destination ident
				socket.send_multipart([logged_users[message[2]], b'MSG', message[3]])
			else:
				socket.send_multipart([ident, b'ERR', message[2] + b' not registered.'])

