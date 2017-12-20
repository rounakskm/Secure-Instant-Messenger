#!/usr/bin/python

'''

Author: Suraj Bhatia

Title: ChatServer.py

Description: Server side program for instant chat using UDP sockets in Python

Usage: python server.py -sp server-port

'''

from socket import *
import argparse
import sys

def signIn(serverSocket, userDatabase, message, address):

	# Receieve username after sign-in
	if message.split()[0] == "SIGN-IN":
		username = message.split()[1]

	# Check for duplicate user, add new USER to database
		if username not in userDatabase:
			userDatabase[username] = address
		else:
			serverSocket.sendto("User "+username+" already exists", address)

	# Handle user exit and remove from logged-in database
	if message == "exit":
		for key, value in userDatabase.items():
			if value == address:
				del userDatabase[key]

	userList = ', '.join(userDatabase.iterkeys())

	return userList, userDatabase


def sendMessage(serverSocket, userDatabase, message, address):

	# Extracting sender name
	for key, value in userDatabase.items():
		if value == address:
			sender = key

	# Extracting receiver name, handling error for no RECEIVER given
	try:
		receiver = message.split()[1]
	except IndexError:
		serverSocket.sendto("Please specify receiver!", address)
		return

	# Extracting actual message to be sent
		m = (' '.join(message.split(' ')[2:]))

	# Send receiever information to sender
	for key, value in userDatabase.items():
		if key == receiver:
			serverSocket.sendto("Send "+str(value[0])+" "+str(value[1]), address)
			return

	# Check for user not logged into chat
	serverSocket.sendto("No such user logged in, try again.", address)

def argsParser():

	# Command-line arguments parser
	parser = argparse.ArgumentParser()
	parser.add_argument("-sp", help="server port number", required=True, type=int)
	args = parser.parse_args()

	return args.sp

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

def main():

	# Parse command line arguments for server port number
	serverPort = argsParser()

	# Create server socket
	serverSocket = createSocket(serverPort)

	# Maintain dictionary mapping of username and addresses
	userDatabase = {}

	try:
		while True:
			# Wait for messages to be received infinitely. handle accordingly
			message, address = serverSocket.recvfrom(65535)

			if message.split()[0] == "SIGN-IN":
				userString, userDatabase = signIn(serverSocket, userDatabase, message, address)

			if message == "list":
				serverSocket.sendto(" Signed in Users: "+str(userString), address)

			if message.split()[0] == "send":
				sendMessage(serverSocket, userDatabase, message, address)

			if message == "exit":
				userString, userDatabase = signIn(serverSocket, userDatabase, message, address)

		serverSocket.close()

	# Handle keyboard interrupt and inform connected clients of break down
	except KeyboardInterrupt:
		for key, value in userDatabase.items():
			serverSocket.sendto("Server Down.", value)

if __name__ == "__main__":
    main()

