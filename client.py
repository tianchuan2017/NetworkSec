import sys
import socket
import re
import base64
import os
import random
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
            sys.exit()

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
	command = input("ftp>")
	if command is "put":
		#send file and hash to FTP server
		pass
	elif command is "get":
		#save/overwrite file+hash from FTP server
		pass
	elif command is "ls":
		#send request for directory listing
		#print listing
		pass
	elif command is "exit":
		#close all files/sockets
		sys.exit()
	else:
		print("Error: invalid command\nAvailable commands are: put, get, ls, exit")

# # Open file
# try:
#     fp = open(sys.argv[2], "rb")
# except Exception as err:
#     print("Invalid file: " + str(err))
#     sys.exit()



# # Load file
# plaintext = fp.read()
# p_len = len(plaintext)

# # Hash file using SHA-256
# hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
# hasher.update(plaintext)
# file_hash = hasher.finalize()


    
#     # Send signed hash, plaintext length, and plaintext
#     s.send(signed_hash)
#     s.send(bytes(str(p_len), 'ascii'))
#     s.send(plaintext)

#     # Start graceful shutdown of connection
#     s.shutdown(socket.SHUT_WR)
#     print("Disconnected from server at: " + str(server_addr))


# # Close files and socket
# fp.close()
# key_file.close()
# s.close()
