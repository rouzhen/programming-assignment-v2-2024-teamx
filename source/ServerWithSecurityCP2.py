# Client ask Server for public key
# Server provides server_signed.crt 
# Client verify this signed certificate using public key from cacsertificate.crt

# TASK 2: Design a protocol to protect the confidentiality of the content of the uploaded file 
# using public key cryptography. For simplicity, the filename does not have to be encrypted.

# CP1
# 1. Client encrypts the file data (byte blocks) before sending
# 2. SecureStore decrypts on receive
# 3. Using PKCS1v15 (min 11 bytes of padding, max 117 bytes data blocks) 
# for RSA key size 1024 bits, encrypt/ decrypt 128 bytes of data at a time
# Client encrypt data in 117-byte and secureStore decrypt data in 128-byte

import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
from signal import signal, SIGINT
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)

def load_keys_and_cert():
    try:
        with open('source/auth/_private_key.pem', 'rb') as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        
        with open('source/auth/server_signed.crt', 'rb') as cert_file:
            server_cert = cert_file.read()

        print("Loaded server certificate:")
        print(f"Size of server certificate: {len(server_cert)} bytes")
        return private_key, server_cert
    except FileNotFoundError as e:
        print(f"Error: {e}. Ensure the required files exist in 'source/auth/'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading keys and certificate: {e}")
        sys.exit(1)


def sign_message(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(), # hashing algorithm used to hash the data before encryption 
    )

global Fernet            # global variable to store the symmetric key    

def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"

    private_key, server_cert = load_keys_and_cert()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()
            print(f"Socket successfully bound to port {port}")
            print(f"Server listening on {address}:{port}")
             
            # if CHECK PASS, begin handshake for file upload
            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 3:
                            print("MODE 3 matched")
                            # Handle authentication handshake
                            auth_message_size = convert_bytes_to_int(read_bytes(client_socket, 8)) # M1 size
                            auth_message = read_bytes(client_socket, auth_message_size)            # M2 

                            signed_message = sign_message(private_key, auth_message)

                            # Send signed message and server certificate
                            print(f"Sending signed M2 of size: {len(signed_message)} bytes")
                            client_socket.sendall(convert_int_to_bytes(len(signed_message)))
                            client_socket.sendall(signed_message)
                            print("Sent signed M2")
                            client_socket.sendall(convert_int_to_bytes(len(server_cert)))
                            client_socket.sendall(server_cert)
                            print("Sent signed M2 and signed server certificate to client")

                        case 4:    # decrypts the symmetric fernet key using server private key.
                            print("MODE 4 matched")
                            # If the packet is for transferring the symmetric fernet key
                            print("Receiving symmetric key...")
                            encrypted_fernet_key_len = convert_bytes_to_int(read_bytes(client_socket, 8)) # M1 size
                            encrypted_fernet_key = read_bytes(client_socket, encrypted_fernet_key_len)    # M2
                            
                            decrypted_fernet_key = private_key.decrypt(
                                encrypted_fernet_key,
                                padding.PKCS1v15()
                            )
                            fernet = Fernet(decrypted_fernet_key)

                        case 0:    # filename
                            print("MODE 0 matched")
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            print(f"Filename: {filename}")

                        case 1:    # file data block
                            print("MODE 1 matched")
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            # Read the encrypted file data length
                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            # --- rz part task 3---
                            # Read the encrypted file data
                            encrypted_file_data = read_bytes(client_socket, file_len)
                            print(f"File data received: {len(encrypted_file_data)} bytes")

                            # B4 decrypting the file data, save recived encrypted file to /recv_files_enc
                            # Write the file with 'recv_' prefix
                            enc_filename = "enc_recv_" + filename.split("/")[-1]
                            with open(
                                f"recv_files_enc/{enc_filename}", mode="wb"
                            ) as fp:
                                fp.write(encrypted_file_data)
                            print(
                                f"Encrypted file saved as recv_files_enc/{enc_filename}"
                            )                

                            decrypted_file_data = fernet.decrypt(encrypted_file_data)
                            # --- rz part task 3 ---       

                            # Aft decrypting the file data, save recived decrypted file to /recv_files
                            filename = "recv_" + filename.split("/")[-1]
                            # Write the file with 'recv_' prefix
                            with open(
                                f"recv_files/{filename}", mode="wb"
                            ) as fp:
                                fp.write(decrypted_file_data)
                            print(
                                f"Finished receiving file in {(time.time() - start_time)}s!"
                            )
                                
                            print("File data decrypted and saved successfully.")
                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Connection closed by client.")
                            s.close()
                            break
                        

    except Exception as e:
        print(e)
        s.close()

def handler(signal_received, frame):
    # Handle any cleanup here
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    exit(0)
    
if __name__ == "__main__":
    # Tell Python to run the handler() function when SIGINT is recieved
    signal(SIGINT, handler)
    main(sys.argv[1:])
