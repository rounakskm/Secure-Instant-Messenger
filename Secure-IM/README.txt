Title: Secure Instant Messaging Web Chat

Author: Soumya Mohanty 
	Suraj Bhatia

Files: server.py
       client.py
       fcrypt.py   	======> Holds all encryption/decryption functions
       keygen/	   	======> Holds script to generate new keys for clients and store all keys
       serverConf.conf  ======> Password verification file for server
       Makefile
	   
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	   
A. PROGRAM DESCRIPTION

This program is a secure interactive instant web chat between multiple clients that supports following main features -

	1. LOG-IN - To securely sign-in to the chat with the server
	2. LIST - To get a list of all the users currently logged into the chat
	3. SEND - To send messages to other users directly (not through server)
	4. EXIT - To exit out of chat
	
The users can simultaneously send and receive messages. For sending messages, the client parses the LIST information received from the server to get the address of the receiever and sends message directly.

For sending/receiving messages, we use UDP sockets in Python. At the time of LOG-IN, a UDP socket in opened on the client which can communicate with the server to securely sign in. The server when initiated, opens up a UDP socket which binds to all its IP interfaces. 

Other features of the chat are -

	1. No duplicate user is allowed to sign in.
	2. If a user exits or logs out unexpectedly, the server handles it gracefully and updates the database of the logged-in users.
	3. Any unrecognized command gives out an error to the client.
	4. If a receiever is not mentioned in the send command or if is not in the logged-in database, the sender is informed about it accordingly.
	5. If the server goes down, all logged-in users can still continue to send messages to each other.
	6. Any empty message is not sent to the receivers. 
	7. Handles socket timeout errors
	8. Handles packets greater than buffer size and sends them in separate chunks
	

B. PROCEDURE TO RUN PROGRAM

The current directory from which the scripts will be executed should have three files -
	
	1. Makefile
	2. keygen/RSAKeygen.py
	2. server.py
	3. client.py

Steps to follow to run program -

	1. make ==> To give the scripts necessary permissions to execute
	
	2. python server.py -s keyGen/serverPublicKey.der keyGen/serverPrivateKey.der -p $PORT   			==> Run server program
	
		OR ./server.py -s keyGen/serverPublicKey.der keyGen/serverPrivateKey.der -p $PORT
		
	3. python client.py -u $USERNAME -c keyGen/$UNAMEPublicKey.der keyGen/$UNAMEPrivateKey.der -skey keyGen/serverPublicKey.der -p $PORT -s $SERVER_IP  	==> Run client program
	
		OR ./client.py -u $USERNAME -c keyGen/$UNAMEPublicKey.der keyGen/$UNAMEPrivateKey.der -skey keyGen/serverPublicKey.der -p $PORT -s $SERVER_IP

It is necessary to run both the scripts with the correct command-line arguments. For any help regarding the arguments, use the following two options -

	1. ./server.py -h
	2. ./client.py -h 


C. USER NAME AND PASSWORDS

	suraj:  surajIsAdmin12!
	rounak: StrongPassword@
	alice:  alice!sbeautiful
	bob:    bob#3sons
	nslab:  nslabcs6740

