import sys
import socket
import struct
import importlib

# Import the ftp and ids modules
# importlib.import_module('ftp')
# importlib.import_module('ids')
from ftp import ftp

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


class ServerConnection():

    def __init__(self):
        # Get server address
        server_addr = get_server_addr()

        # Open socket
        self.s = socket.socket(socket.AF_INET)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Open Socket
        try:
            self.s.bind(server_addr)
            self.s.listen(1)
            print("Awaiting connections on: " + str(self.s.getsockname()))

            # Accept connection
            self.conn, self.addr = self.s.accept()
            print("Connection from: " + str(self.addr))
        except Exception as err:
            print("Error opening socket: " + str(err))
            sys.exit()

    def send(self, bytes):
        return self.conn.send(bytes)

    def get_message(self):
        data = self.conn.recv(4)
        msg_len = struct.unpack("I", data)[0]
        # print("message len: " + str(msg_len))
        msg = b""
        while (len(msg) < msg_len):
            msg = msg + self.conn.recv(1)

        # print("message: " + str(msg))
        return msg


print("FTP Client Starting...")

# Initialize a socket connection
conn = ServerConnection()

while True:
    # Receive command string
    command = conn.get_message()

    # Send the command to the ftp protocol
    ftp_exit_result = ftp(command, conn)

    if ftp_exit_result:
        # close all files/sockets
        conn.s.shutdown(socket.SHUT_WR)
        print("Disconnected from client at: " + str(conn.addr))
        conn.s.close()
        sys.exit()
