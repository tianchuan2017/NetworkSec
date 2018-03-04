import sys
import socket
import re
import base64
import os
import random
import struct
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

print("FTP Client Starting...")

def get_server_addr():
    
    # Retreive server ip address
    try:
        server_ip = socket.gethostbyname(socket.gethostname())
    except Exception as err:
        print("Error fetching local ip address: " + str(err))
        sys.exit()
    
    while True:
        try:
            server_port = int(input("Please enter the port number of this FTP Server: "))
            break
        except Exception as err:
            print("Error: Invaid Port Number: " + str(err))
            
    # Create a server address tuple
    server_addr = (server_ip, server_port)

    return server_addr

def get_message(conn):
    data = conn.recv(4)
    msg_len = struct.unpack("I", data)[0]
    #print("message len: " + str(msg_len))
    msg = b""
    while(len(msg) < msg_len):
        msg = msg + conn.recv(1)
        
    #print("message: " + str(msg))
    return msg
     
def is_valid_file(filename):
    if "/" in filename or "\\" in filename:
        print("Error: Filename cannot be a path")
        return False
    elif not os.path.isfile(filename):
        print("Error: " + filename + " does not exist")
        return False
    else:
        return True
        
        
# Create Ferent instance to encrypt hashes during storage
#key = Fernet.generate_key()
#f = Fernet(key)

# Get server address
server_addr = get_server_addr()

# Open socket       
s = socket.socket(socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   

# Open Socket
try:
    s.bind(server_addr)
    s.listen(1)
    print("Awaiting connections on: " + str(s.getsockname()))
    
    # Accept connection
    conn, addr = s.accept()
    print("Connection from: " + str(addr))
except Exception as err:
    print("Error opening socket: " + str(err))
    sys.exit()

while True:
    # Receive command string
    command = get_message(conn)

    if command == b"put":
        # Receive message components
        digest = get_message(conn)
        filename = get_message(conn).decode('ascii')
        plaintext = get_message(conn)
            
        # Encrypt hash
        #digest_token = f.encrypt(digest)
        digest_token = digest
        
        # Write file                                                                                                                                                                                                                                   to disk
        fout = open(filename,'wb')
        fout.write(plaintext)
        fout.close()
        
        # Write hash to disk
        fout = open((filename + ".hash"),'wb')
        fout.write(digest_token)
        fout.close()

        print("Plaintext written to: " + filename)
        print("Hash written to: " + filename + ".hash")
        
    elif command == b"get":
        #send file/hash to client

        # Get filename from client
        filename = get_message(conn).decode('ascii')

        # Check if the file is available
        has_file = 0
        if is_valid_file(filename):
            has_file = 1
            
            # Let the client know the file is available
            conn.send(struct.pack("I", 1))
            conn.send(bytes([has_file]))
            
            # Open and load the file
            fp = open(filename, "rb")
            plaintext = fp.read()
            fp.close()
            
            # Send filename
            conn.send(struct.pack("I", len(filename)))
            conn.send(filename.encode('ascii'))
            
            # Send file
            conn.send(struct.pack("I", len(plaintext)))
            conn.send(plaintext)
            print("Sent file: " + filename)
            
            # Check is hash is available
            if is_valid_file(filename + ".hash"):
                fp = open((filename + ".hash"), "rb")
                digest_token = fp.read()
                fp.close()
                
                # try-except used in case we want to encrypt the file hashes
                try:
                    #digest = f.decrypt(digest_token)
                    digest = digest_token
                    has_hash = 1
                except Exception as err:
                    print("Error: Could not decrypt hash: " + str(err))
                    has_hash = 0
            
            # Send has_hash
            conn.send(struct.pack("I", 1))
            conn.send(bytes([has_hash]))

            if has_hash == 1:
                # Send hash
                conn.send(struct.pack("I", len(digest)))
                conn.send(digest)
                print("Sent hash: " + (filename + ".hash"))
            else:
                print("No hash sent")
        else:
            # Let the client know the file is unavailable
            conn.send(struct.pack("I", 1))
            conn.send(bytes([has_file]))
        
    elif command == b"ls":
        #retreive directory listing
        ls = os.listdir()
        j_ls = json.dumps(ls).encode('ascii')
        
        #send listing to client
        conn.send(struct.pack("I", len(j_ls)))
        conn.send(j_ls)
        
    elif command == b"exit":
        #close all files/sockets
        s.shutdown(socket.SHUT_WR)
        print("Disconnected from client at: " + str(addr))
        s.close()
        sys.exit()
    else:
        print("Error: Invalid command\nAvailable commands are: put, get, ls, exit")

