import sys
import socket
import re
import base64
import os
import random
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

print("FTP Client Starting...")

def get_server_addr():
    # Parse server IP address
    while True:
        try:
            server_ip = input("Please enter the IP address of the FTP Server: ")
            socket.inet_aton(server_ip)
            break
        except Exception as err:
            print("Invalid IP address: " + str(err))

    # Parse server port number
    while True:
        try:
            server_port = int(input("Please enter the port number of the FTP Server: "))
            break
        except Exception as err:
            print("Invaid Port Number: " + str(err))

    # Create a server address tuple
    server_addr = (server_ip, server_port)

    return server_addr

def connect_to_server(s, server_addr):
	try:
		# Connect to server
		s.connect(server_addr)
		print("Connected to server at: " + str(server_addr))
		return True
	except Exception as err:
		print("Error connecting to server: " + str(err))
		return False
    
def is_valid_file(filename):
    if "/" in filename or "\\" in filename:
        print("Error: Filename cannot be a path")
        return False
    elif not os.path.isfile(filename):
        print("Error: " + filename + " does not exist")
        return False
    else:
        return True
    
def hash_file(plaintext):
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(plaintext)
    file_hash = hasher.finalize()
    return file_hash
    
# Open socket       
s = socket.socket(socket.AF_INET)    

# Try to connect to the specified address
while True:
	server_addr = get_server_addr()
	if connect_to_server(s, server_addr):
		break

# At this point, we are connected to a server
while True:
    # Enter command
    command = input("ftp>").split()
    print(command)
    print(command[0])
    
    if command[0] == "put":
        #send file and hash to FTP server
        
        #is the file valid?
        filename = command[1]
        if is_valid_file(filename):
            fp = open(filename, "rb")
            
            # Load file
            plaintext = fp.read()
            p_len = len(plaintext)
            fp.close()
            
            # Generate Hash
            digest = hash_file(plaintext)
            
            # Send Command
            s.send(struct.pack("I", len(command[0])))
            s.send(command[0].encode('ascii'))

            # Send Hash
            s.send(struct.pack("I", len(digest)))
            s.send(digest)
            
            # Send filename
            s.send(struct.pack("I", len(filename)))
            s.send(filename.encode('ascii'))
            
            # Send file
            s.send(struct.pack("I", p_len))
            s.send(plaintext)
            
    elif command[0] == "get":
		#save/overwrite file+hash from FTP server
        pass
    elif command[0] == "ls":
		#send request for directory listing
		#print listing
        pass
    elif command[0] == "exit":
		#close all files/sockets
        s.shutdown(socket.SHUT_WR)
        print("Disconnected from server at: " + str(server_addr))
        s.close()
        sys.exit()
    else:
        print("Error: invalid command\nAvailable commands are: put, get, ls, exit")