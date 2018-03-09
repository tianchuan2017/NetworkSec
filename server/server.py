import sys
import socket
import struct
import math
import os
import datetime

# Import the ftp and ids modules
from ftp import ftp
from ids import IDS

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
            print("Error: Invalid Port Number: " + str(err))

    # Create a server address tuple
    server_addr = (server_ip, server_port)

    return server_addr


class ServerConnection():

    message_len = 1016  # TODO: figure out exactly what this value should be
    header_len = 8
    packet_len = message_len + header_len

    def __init__(self):
        # Open log file
        log_filename = "server.log"
        self.log_file = open(log_filename, 'a')
            
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
            self.log_event("Connection from: " + str(self.addr))
        except Exception as err:
            print("Error opening socket: " + str(err))
            sys.exit()

    def log_event(self, event):
        timestamp = str(datetime.datetime.now())
        self.log_file.write(timestamp + "\t" + event + "\r\n")

    def get_message(self):
        # Initialize expected index at 0
        expected_idx = 0
        
        msg = b''
        
        while True:
            # Receive packet 
            recv_buf = self.conn.recv(ServerConnection.packet_len)
        
            # Have the IDS inspect the packet
            ids_response = ids.inspect_message(recv_buf)
            if ids_response is not None:
                # An intrusion was detected. Handle it.
                self.handle_intrusion(ids_response)
            else:
                # Parse header
                header = recv_buf[0:ServerConnection.header_len]
                byte_idx = struct.unpack(">II", header)[0]
                msg_len = struct.unpack(">II", header)[1]
                
                # If the packet number is as expected
                if byte_idx == expected_idx:
                    # Determine portion of packet that contains message
                    start_idx = ServerConnection.header_len
                    end_idx = start_idx + ServerConnection.message_len
                    if(byte_idx + ServerConnection.message_len > msg_len):
                        end_idx = msg_len - byte_idx + ServerConnection.header_len
                        
                    # Copy buffer 
                    msg = msg + recv_buf[start_idx: end_idx]

                    # If we have collected the entire message, exit loop
                    if len(msg) == msg_len:
                        break
                        
                    # Increment expected index
                    expected_idx = byte_idx + ServerConnection.message_len
                else:
                    # Error, a packet was dropped
                    print('Packet Dropped. Exiting...')
                    sys.exit(1) 
                    #TODO Handle a dropped packet
                    #TODO Handle dropped last packet
            
        return msg
            
    def send_message(self, msg):
        msg_len = len(msg)
        packet_num = math.ceil(msg_len / ServerConnection.message_len)
        
        # Section data into buffer and send
        for x in range(0, packet_num):
            # Set start/end indicies to copy to buffer
            start_idx = x*ServerConnection.message_len
            end_idx = start_idx + ServerConnection.message_len
            if(end_idx > msg_len):
                end_idx = msg_len
            
            # Create an empty packet
            packet = bytearray(ServerConnection.message_len + ServerConnection.header_len)
            
            # Insert Header
            # Contains byte sequence number and total message length
            header = struct.pack(">II", start_idx, msg_len)
            packet[0:ServerConnection.header_len] = header

            # Copy portion of message to buffer
            data = msg[start_idx: end_idx]
            packet[ServerConnection.header_len:ServerConnection.header_len + len(data)] = data

            # Have the IDS inspect the packet
            ids_response = ids.inspect_message(packet)
            if ids_response is not None:
                # An intrusion was detected. Handle it.
                self.handle_intrusion(ids_response)
            else:
                self.conn.send(packet)

    def handle_intrusion(self, ids_response):
        # TODO Handle an intrusion
        self.log_event('Intrusion from: {} Pattern ID: {}'.format(self.addr, ids_response))
        print('!!!Intrusion Detected!!!')
        self.close_connection()
        sys.exit(1)

    def close_connection(self):
        # Close all files/sockets
        self.s.shutdown(socket.SHUT_WR)
        print("Disconnected from client at: " + str(self.addr))
        self.log_event("Disconnected from client at: " + str(self.addr))
        self.s.close()
        self.log_file.close()


print('Intrusion Detection System Starting...')

# Initialize an IDS
ids = IDS()

print("FTP Server Starting...")

# Initialize a socket connection
conn = ServerConnection()

# Change to the files/ directory, where all files will be stored
os.chdir('files/')

while True:
    # Receive command string
    command = conn.get_message()

    # Send the command to the ftp protocol
    ftp_exit_result = ftp(command, conn)

    if ftp_exit_result:
        # Close and exit
        conn.close_connection()
        sys.exit()
