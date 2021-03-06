import os
import json

def is_valid_file(filename, path_prefix=''):
    if "/" in filename or "\\" in filename:
        print("Error: Filename cannot be a path")
        return False
    elif not os.path.isfile(path_prefix + filename):
        print("Error: " + filename + " does not exist")
        return False
    # Ubuntu max filename length = 255 bytes
    elif len(filename) > 255:
        print("Error: Filename too long")
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

        conn.log_event("Received request: [" + command.decode('ascii') + " " + filename + "] from " + str(conn.addr))

        # Write file                                                                                                                                                                                                                                   to disk
        fout = open("files/" + filename, 'wb')
        fout.write(plaintext)
        fout.close()

        # Write hash to disk
        fout = open(('data/' + filename + ".hash"), 'wb')
        fout.write(digest)
        fout.close()

        print("Plaintext written to: files/" + filename)
        conn.log_event("Plaintext written to: files/" + filename)
        print("Hash written to: data/" + filename + ".hash")
        conn.log_event("Hash written to: data/" + filename + ".hash")

    elif command == b"get":
        # Get filename from client
        filename = conn.get_message().decode('ascii')

        conn.log_event("Received request: [" + command.decode('ascii') + " " + filename + "] from " + str(conn.addr))

        # Check if the file is available
        has_file = 0
        if is_valid_file(filename, path_prefix='files/'):
            has_file = 1

            # Let the client know the file is available
            conn.send_message(bytes([has_file]))

            # Open and load the file
            fp = open("files/" + filename, "rb")
            plaintext = fp.read()
            fp.close()

            # Send filename
            conn.send_message(filename.encode('ascii'))

            # Send file
            conn.send_message(plaintext)
            print("Sent file: files/" + filename)
            conn.log_event("Sent file: files/" + filename)

            # Check is hash is available
            has_hash = 0
            if is_valid_file(filename + ".hash", path_prefix='data/'):
                has_hash = 1
                fp = open(('data/' + filename + ".hash"), "rb")
                digest = fp.read()
                fp.close()

            # Send has_hash
            conn.send_message(bytes([has_hash]))

            if has_hash == 1:
                # Send hash
                conn.send_message(digest)
                print("Sent hash: " + ('data/' + filename + ".hash"))
                conn.log_event("Sent hash: " + ('data/' + filename + ".hash"))
            else:
                print("No hash sent")
                conn.log_event("No hash sent")
        else:
            # Let the client know the file is unavailable
            conn.send_message(bytes([has_file]))
            conn.log_event("files/" + filename + " is unavailable")

    elif command == b"ls":
        # retreive directory listing
        ls = os.listdir('files/')
        j_ls = json.dumps(ls).encode('ascii')

        conn.log_event("Received request: [" + command.decode('ascii') + "] from " + str(conn.addr))

        # send listing to client
        conn.send_message(j_ls)

    elif command == b"exit":
        # Flag the encapsulating server to exit
        should_exit = True

    else:
        print("Error: Invalid command: " + command.decode('ascii'))

    return should_exit
