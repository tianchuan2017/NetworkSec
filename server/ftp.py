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


def is_valid_file(filename):
    if "/" in filename or "\\" in filename:
        print("Error: Filename cannot be a path")
        return False
    elif not os.path.isfile(filename):
        print("Error: " + filename + " does not exist")
        return False
    else:
        return True


def ftp(command, conn):
    """
    :param command: The command {put, get, ls, exit) to execute.
    :param conn: The ServerConnection
    :return should_exit: bool that tells the server whether to exit
    """

    # Flag that determines if the server should exit when done
    should_exit = False

    if command == b"put":
        # Receive message components
        digest = conn.get_message()
        filename = conn.get_message().decode('ascii')
        plaintext = conn.get_message()

        # Encrypt hash
        # digest_token = f.encrypt(digest)
        digest_token = digest

        # Write file                                                                                                                                                                                                                                   to disk
        fout = open(filename, 'wb')
        fout.write(plaintext)
        fout.close()

        # Write hash to disk
        fout = open((filename + ".hash"), 'wb')
        fout.write(digest_token)
        fout.close()

        print("Plaintext written to: " + filename)
        print("Hash written to: " + filename + ".hash")

    elif command == b"get":
        # send file/hash to client

        # Get filename from client
        filename = conn.get_message().decode('ascii')

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
                    # digest = f.decrypt(digest_token)
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
        # retreive directory listing
        ls = os.listdir()
        j_ls = json.dumps(ls).encode('ascii')

        # send listing to client
        conn.send(struct.pack("I", len(j_ls)))
        conn.send(j_ls)

    elif command == b"exit":
        # Flag the encapsulating server to exit
        should_exit = True

    else:
        print("Error: Invalid command\nAvailable commands are: put, get, ls, exit")

    return should_exit
