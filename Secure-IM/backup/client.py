#!/usr/bin/python

'''

Author: Suraj Bhatia

Title: ChatClient.py

Description: Client side program for instant chat using UDP sockets in Python

Usage: python client.py -u USERNAME -sip server-ip -sp server-port

'''

from socket import *
import argparse
import sys
import select

def prompt():

	sys.stdout.write('+> ')
	sys.stdout.flush()

def sendToServer(message, socket, username, addr):

	# User SIGN-IN and send USERNAME to server
	if message == "SIGN-IN":
		try :
			socket.sendto("SIGN-IN "+username, addr)

		except error, msg:
			print 'Error Code : ' + str(msg)
			sys.exit()

	# For send command, request receiver information from server
	if message.split()[0] == "send":
		try :
			socket.sendto(message, addr)

		except error, msg:
			print 'Error Code : ' + str(msg)
			sys.exit()

	# Retrieve list of users connected to chat from server
	if message == "list":
		try :
			socket.sendto("list", addr)
			socket.settimeout(2)
			data, server = socket.recvfrom(65535)
			print str("<-"+data)

		except error, msg:
			print 'Error Code : ' + str(msg)
			sys.exit()

	# Inform server that client is leaving chat
	if message == "exit":
		try :
			socket.sendto(message, addr)

		except error, msg:
			print 'Error Code : ' + str(msg)
			sys.exit()

def createSocket(ip, port):

	# Create socket and handle failure
	try:
		clientSocket = socket(AF_INET, SOCK_DGRAM)

	except socket.error:
		print 'Failed to create socket'
		sys.exit(0)

	return clientSocket

def argsParser():

	# Command-line arguments parser
	parser = argparse.ArgumentParser()

	parser.add_argument("-u", help="USERNAME", required=True)
	parser.add_argument("-sip", help="server-ip", required=True)
	parser.add_argument("-sp", help="port", type=int, required=True)

	args = parser.parse_args()

	return args.u, args.sp, args.sip

def main():

	# Retrieve username, server port and IP from command-line
	username, port, ip = argsParser()
	addr = (ip, port)

	# Create client UDP socket
	clientSocket = createSocket(ip, port)

	# Send SIGN-IN message to server after socket creation
	sendToServer("SIGN-IN", clientSocket, username, addr)
	prompt()

	try:
		while True:

			# Manage list of different sockets
			socketList = [sys.stdin, clientSocket]
			readSocket, writeSocket, errorSocket = select.select(socketList, [], [])

			for sock in readSocket:
				if sock == clientSocket:
					# Keep checking for received messages from server or other users
					try:
						data = clientSocket.recv(65535)

					except error:
						break

					if not data:
						sys.exit()

					else:
						# Retrieve receiver information from server to send message directly
						if data.split()[0] == "Send":
							receiverIp = data.split()[1]
							receiverPort = int(data.split()[2])
							receiver = (receiverIp, receiverPort)

							try:
								# Get actual message from send command
								m = message.split()[2]
								m = (' '.join(message.split(' ')[2:]))

								# Handle socket receiver buffer overflow
								if len(str(m)) <= 65494:
									clientSocket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+str(m)), receiver)

								# Send in chunks if total message larger > 65535
								else:
									clientSocket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+m[0:65494]), receiver)
									clientSocket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+m[65494:]), receiver)

							# Do not send empty messages
							except IndexError:
								print "\n<- Please enter some message!"

						# Exit from chat if server is down
						elif data == "Server Down.":
							print "\n+> Server disconnected, try again later."
							sys.exit()

						# Handle duplicate user log-in and exit
						elif data == "User "+username+" already exists.":
							sys.stdout.write('\n<- '+data+'\n')
							sys.exit()

						# Display any other legitimate messages from other users
						else:
							sys.stdout.write('\n<- '+data+'\n')

						prompt()
				else:
					# Take input from user
					message = raw_input()

					# Handle user exit
					if message == "exit":
						sendToServer(message, clientSocket, username, addr)
						clientSocket.close()
						sys.exit(0)

					# Blank command goes to next line
					elif message =="":
						prompt()

					# Check for message format
					elif message.split()[0] == "send":
						try:
							sendToServer(message, clientSocket, username, addr)

						except IndexError:
							print "+> Incorrect send format, please try again."
							prompt()

					# Request from server list of users logged in to chat
					elif message == "list":
						sendToServer(message, clientSocket, username, addr)
						prompt()

					# Handle invalid chat commands
					else:
						print "+> Command not supported, please try again."
						prompt()

	# Handle keyboard interrup, notify server and exit from chat gracefully
	except KeyboardInterrupt:
		sendToServer("exit", clientSocket, username, addr)
		clientSocket.close()
		sys.exit(0)

if __name__ == "__main__":
    main()
