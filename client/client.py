import sys
import socket
import os
import struct
import json
import math
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

message_len = 1016  # TODO: figure out exactly what this value should be
header_len = 8
packet_len = message_len + header_len

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


def get_message(conn):
    # Initialize expected index
    expected_idx = 0

    # Initialize empty message
    msg = b''

    try:
        while True:
            # Receive packet containing size information
            recv_buf = conn.recv(packet_len)

            # Build header
            header = recv_buf[0:header_len]
            byte_idx = struct.unpack(">II", header)[0]
            msg_len = struct.unpack(">II", header)[1]

            # If we receive a packet with an expected byte index
            if byte_idx == expected_idx:

                # Determine portion of packet that contains message
                start_idx = header_len
                end_idx = start_idx + message_len
                if (byte_idx + message_len > msg_len):
                    end_idx = msg_len - byte_idx + header_len

                # Append buffer to message
                msg = msg + recv_buf[start_idx: end_idx]

                # Exit loop if we have collected the entire message
                if len(msg) == msg_len:
                    break

                # Increment expected index
                expected_idx = byte_idx + message_len

            else:
                # Error, a packet was dropped
                raise ConnectionError('Packet Dropped. File not saved.')
                sys.exit(1)  # TODO Handle a dropped packet
    except socket.timeout as err:
        raise Exception('Server not responding. Connection closed')

    return msg


def send_message(conn, msg):
    msg_len = len(msg)
    packet_num = math.ceil(msg_len / message_len)

    # Section data into buffer and send
    for x in range(0, packet_num):
        # Set start/end indicies of message to copy to buffer
        start_idx = x * message_len
        end_idx = start_idx + message_len
        if (end_idx > msg_len):
            end_idx = msg_len

        # Create an empty packet
        packet = bytearray(packet_len)

        # Insert Header
        # Contains byte sequence number and total message length
        header = struct.pack(">II", start_idx, msg_len)
        packet[0:header_len] = header

        # Copy portion of message to buffer
        data = msg[start_idx: end_idx]
        packet[header_len:header_len + len(data)] = data

        # Send packet
        conn.send(packet)


# Open socket
s = socket.socket(socket.AF_INET)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.settimeout(5)

# Try to connect to the specified address
while True:
    server_addr = get_server_addr()
    if connect_to_server(s, server_addr):
        # At this point, we are connected to a server
        try:
            while True:
                # Enter command
                command = input("ftp> ").split()

                try:
                    if command[0] == "put":
                        # send file and hash to FTP server
                        if len(command) == 2:
                            # is the file valid?
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
                                send_message(s, command[0].encode('ascii'))

                                # Send Hash
                                send_message(s, digest)

                                # Send filename
                                send_message(s, filename.encode('ascii'))

                                # Send file
                                send_message(s, plaintext)
                        else:
                            print("Error: Incomplete Command\nput [filename]")

                    elif command[0] == "get":
                        if len(command) == 2:
                            # save/overwrite file+hash from FTP server
                            filename = command[1]

                            # Send Command
                            send_message(s, command[0].encode('ascii'))

                            # Send filename
                            send_message(s, filename.encode('ascii'))

                            has_file = int.from_bytes(get_message(s), byteorder='big')
                            if has_file == 1:
                                # Receive filename
                                filename = get_message(s).decode('ascii')
                                # Receive file
                                data = get_message(s)

                                has_hash = int.from_bytes(get_message(s), byteorder='big')
                                if has_hash == 1:
                                    # Receive hash
                                    server_digest = get_message(s)
                                    # Run local hash
                                    digest = hash_file(data)
                                    # Verify file integrity
                                    if server_digest == digest:
                                        fout = open(filename, 'wb')
                                        fout.write(data)
                                        fout.close()
                                    else:
                                        print("Hash does not match!\nFile not saved.")
                                else:
                                    print("No hash available.\nFile not saved.")
                            else:
                                print("File unavailable on server")
                        else:
                            print("Error: Incomplete command.\nget [filename]")

                    elif command[0] == "ls":
                        # send request for directory listing
                        send_message(s, command[0].encode('ascii'))

                        # receive directory listing
                        j_ls = get_message(s).decode('ascii')
                        ls = json.loads(j_ls)

                        # print listing
                        for item in ls:
                            print(item)

                    elif command[0] == "exit":
                        try:
                            # Send Command
                            send_message(s, command[0].encode('ascii'))
                            s.shutdown(socket.SHUT_WR)
                        except ConnectionError as err:
                            print("Connection closed by server.")

                        # close all files/sockets
                        print("Disconnected from server at: " + str(server_addr))
                        s.close()
                        sys.exit()
                    else:
                        print("Error: invalid command\nAvailable commands are: put, get, ls, exit")
                except ConnectionError as err:
                    print("Connection Error: " + str(err))

        except Exception as err:
            print("Error: Connection closed\n")
            s.close()
            sys.exit()
