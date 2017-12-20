#!/usr/bin/env python
#
'''
Simple Chat Program that allows users to register, request the list of registered users,
and send a message to another user through the server. This code can get you started with
your CS4740/6740 project.
Note, that a better implementation would use google protobuf more extensively, with a
single message integrating both control information such as command type and other fields.
See the other provided tutorial on Google Protobuf.
Also, note that the services provided by this sample project do not nessarily satify the
functionality requirements of your final instant messaging project.
'''

__author__      = "Guevara Noubir"

import zmq
import sys
import time
import base64
import argparse
import sys
import os
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import ast

sys.path.insert(0, '/home/sbhatia/git/CS-6740/FinalProject/keyGen')
sys.path.insert(0, '/home/sbhatia/git/CS-6740/FinalProject/protobuf')

import messaging_app_pb2

from fcrypt import AESEncryption
from fcrypt import AESDecryption
from fcrypt import RSAEncryption
from fcrypt import RSADecryption
from fcrypt import messageSigning
from fcrypt import messageVerification
from fcrypt import loadRSAPublicKey
from fcrypt import loadRSAPrivateKey

NOT_REGISTERED = 0
REGISTERED = 1

def serverAuthentication():

	R1 = randint(0, 1000)

	#print "R1: "+str(R1)

	firstMessage = {'message': "LOGIN", 'random': R1}

	cipherLogin = RSAEncryption(serverPubKey, str(firstMessage))

	socket.send_multipart([cipherLogin, username, user.SerializeToString()])

	helloMessage = socket.recv_multipart()

	#print "HELLO: "+str(helloMessage)

	#print "Incremented R1: "+helloMessage[0].split(" ")[1] #prints R1 from server

	R1 += 1

	if int(helloMessage[0].split(" ")[1]) != R1:
		sys.exit("Verification failed!")
		#print "R1 check PASS"

	#Generating R2
	R2 = randint(0, 1000)
	#print 'Genereated R2: '+str(R2)
	#load the public key file to be sent 
	f = open(senderPubKeyFile, 'r')
	publicKeyFile = f.read()
	f.close()	
	
	secondCipherKey = RSAEncryption(serverPubKey, publicKeyFile)
	secondCipherNum = RSAEncryption(serverPubKey, str(R2))

	secondMessage = {"key":secondCipherKey, "random":secondCipherNum}

	secondHash = messageSigning(sendPriKey, str(secondMessage))

	socket.send_multipart([str(secondMessage), secondHash, user.SerializeToString()])

	# Accept challenge and decrypt it
	challenge_dict = socket.recv_multipart()
	
	challenge_dict = ast.literal_eval(challenge_dict[0]) #Converting to dict
	
	challenge = RSADecryption(sendPriKey, challenge_dict['challenge'])		
	challenge_R2 = RSADecryption(sendPriKey, challenge_dict['random'])

	#incrementing R2
	R2 = int(R2)+1
	#print 'R2: '+ str(R2)
	#print 'Challenge R2: '+challenge_R2
	#Check if R2 is incremented
	if not R2 == int(challenge_R2):
		sys.exit("Random number doesnt match") 
	
	auth_status = 'fail'
	while (auth_status == 'fail'):
		uname = raw_input("Enter username: ")
		# Make password invisible
		password = raw_input("Enter password: ")

		#Hashing the password
		pass_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		pass_digest.update(password)
		password = pass_digest.finalize()
		password = base64.b64encode(password)

		#finding answer of the challenge
		challenge_ans = break_hash(challenge)

		#Incrementing the random number
		R2 = int(R2)+1
		#print "sent: "+ str(R2)

		# Create DH keys

		

		#Create the message dictionary
		thirdMessage = {"challenge_ans":challenge_ans, "random":R2, "uname" : uname, "password": password, 'dh_key': dh_public_key}

		#Encrypt the message and sign it then send

		thirdMessage = RSAEncryption(serverPubKey, str(thirdMessage))
		#print 'encrypt works'
		thirdHash = messageSigning(sendPriKey, thirdMessage)
		#print 'hashing works'
		#Send challenge_and, uname, password to the server for authentication
		socket.send_multipart([str(thirdMessage), thirdHash])

		#Receive message and see if server auth success or not 
		auth_msg = socket.recv_multipart()
		auth_msg = RSADecryption(sendPriKey, auth_msg[0])
		auth_msg = ast.literal_eval(auth_msg)
		#print 'auth_msg:  '		
		#print auth_msg
		#print type(auth_msg)

		#Do random number check
		R3 = R2+1
		if not R3 == auth_msg['random']:
			sys.exit("Random number doesnt match")

		# Terminate client session after three attempts
		if auth_msg['status'] == 'FAIL':
			print 'Incorrect credentials. Please try again.'
		elif auth_msg['status'] == 'KILL':
			sys.exit('All attempts exhausted. Start new session!!!')
		elif auth_msg['status'] == 'WELCOME':
			print 'Authentication Successful'
			auth_status = 'pass'			
			#Receive TokenId
			token_id = auth_msg['token_id']
			print 'TokenId: '+ token_id 
			return token_id

#def c2c_authentication():


		

#Function used to bruteforce and find answer of the challenge
def break_hash(challenge_hash):
	#print "bruteforce begins"	
	for num in range(1,1000000):
		challenge_digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    		challenge_digest.update(str(num))
		num_hash = challenge_digest.finalize()
		num_hash = base64.b64encode(num_hash)
		
		if num_hash == challenge_hash:
			return num



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

sendPriKey = loadRSAPrivateKey(args.c[1], "der")

senderPubKeyFile = args.c[0]

#sendPubKey = loadRSAPublicKey(args.c[0], "der")

serverPubKey = loadRSAPublicKey(args.skey[0], "der")

#  Prepare our context and sockets
context = zmq.Context()

# We are using the DEALER - ROUTER pattern see ZMQ docs
socket = context.socket(zmq.DEALER)
socket.connect("tcp://%s:%s" %(args.server, args.server_port))

# Set username based on args parameters from the command line or default
username = args.user


# Initialize state of client
status = NOT_REGISTERED

# Function to print a prompt character
def print_prompt(c):
    sys.stdout.write(c)
    sys.stdout.flush()

# Create the google protopub message -- format is defined in messaging-app.proto
# This is in some sense for illustration what you can do with protbub
user = messaging_app_pb2.User()

# Set username field in user message
user.name = username

token_id = serverAuthentication()

# Send REGISTER message to server
# Use the send_multipart API of ZMQ -- again to illustrate some of the capabilities of ZMQ
#socket.send_multipart([b"REGISTER", username, user.SerializeToString()])

# An alternative would have been to send the username directly
#socket.send_multipart([b"REGISTER", username])

# We are going to wait on both the socket for messages and stdin for command line input
poll = zmq.Poller()
poll.register(socket, zmq.POLLIN)
poll.register(sys.stdin, zmq.POLLIN)


while(True):

	sock = dict(poll.poll())
	
	# if message came on the socket
	if socket in sock and sock[socket] == zmq.POLLIN:
		message = socket.recv_multipart()

	#print message

	try:

	# If LIST command
		if message[0] == 'LIST' and len(message) > 1:
			d = base64.b64decode(message[1])
			d = RSADecryption(sendPriKey, d)
			list_users = ast.literal_eval(d)
			print("\n Currently logged on: %s\n" % (d))
			print_prompt(' <- ')

	# If MSG
		elif message[0] == 'MSG' and len(message) > 1:
			d = message[1] #base64.b64decode(message[1])
			print("\n  > %s" % (d))
			print_prompt(' <- ')

	# If response to the REGISTER message
		elif message[0] == 'REGISTER' and len(message) > 1 and status != REGISTERED:
			d = message[1] #base64.b64decode(message[1])
			print("\n <o> %s" % (d))
			status = REGISTERED
			print_prompt(' <- ')

	# If error encountered by server
		elif message[0] == 'ERR' and len(message) > 1:
			d = message[1] #base64.b64decode(message[1])
			print("\n <!> %s" % (d))
			print_prompt(' <- ')

		elif message[0] == 'BYE' and len(message) > 1:

			d = base64.b64decode(message[1]) #base64.b64decode(message[1])
			d = RSADecryption(sendPriKey, d)

			try:
				d = ast.literal_eval(d)
			except ValueError:
				continue

			if d['tokenid'] == token_id:
				print("Exiting from chat\n")
				socket.close()
				sys.exit()
			
	except IndexError:
		continue


	# if input on stdin -- process user commands
	if sys.stdin.fileno() in sock and sock[0] == zmq.POLLIN:
		userin = sys.stdin.readline().splitlines()[0]
		print_prompt(' <- ')

		# get the first work on user input
		cmd = userin.split(' ', 2)

		# print "COMMAND: "+str(cmd[0])

		# if it's list send "LIST", note that we should have used google protobuf
		if cmd[0] == 'LIST':

			# socket.send(b"LIST")

			listRequest = {"ident": username, "message": "LIST"}

			cipherLogin = RSAEncryption(serverPubKey, str(listRequest))

			socket.send_multipart([cipherLogin, username, user.SerializeToString()])	

		# A user can issue a register command at anytime, although not very useful
		#  since client sends the REGISTER message automatically when started
		elif cmd[0] == 'REGISTER':
			user = messaging_app_pb2.User()
			user.name = username

			# Note that the username is sent both without and with protobuf
			socket.send_multipart([b"REGISTER", username, user.SerializeToString()])

		# SEND command is sent as a three parts ZMQ message, as "SEND destination message"
		elif cmd[0] == 'SEND' and len(cmd) > 2:

			# Perform client-client authentication with server

			#c2c_authentication()

			print list_users['Alice']

			if cmd[1] in list_users:
				print cmd[1]+" is in list with address "+str((list_users[cmd[1]]))

				socket.send_multipart([list_users[cmd[1]], b'HI', b'BYE'])

				# socket.send_multipart([list_users[cmd[1]], cmd[0], cmd[1], cmd[2]])

			else:
				print "User not in list, perform LIST operation again!"

			socket.send_multipart([cmd[0], cmd[1], cmd[2]])

		elif cmd[0] == 'exit' or cmd[0] == 'quit' or cmd[0] == 'q':
			
			exit_message = {"tokenid": token_id, "message": "LOGOFF", "username": username}

			cipher_exit = RSAEncryption(serverPubKey, str(exit_message))

			socket.send_multipart([cipher_exit, username, user.SerializeToString()])

		else:
			continue
			#message = ''

	



