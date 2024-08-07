# TASK 2: Design a protocol to protect the confidentiality of the content of the uploaded file 
# using public key cryptography. For simplicity, the filename does not have to be encrypted.

# CP1
# 1. Client encrypts the file data (byte blocks) before sending
# 2. SecureStore decrypts on receive
# 3. Using PKCS1v15 (min 11 bytes of padding, max 117 bytes data blocks) 
# for RSA key size 1024 bits, encrypt/ decrypt 128 bytes of data at a time

import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Logging imports
import psutil
import os
import logging

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
    Ensures client reliably receives the expected number of bytes for each message
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

def load_certificates():
    with open('source/auth/cacsertificate.crt', 'rb') as cert_file:  # Adjusted file path
        ca_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
    return ca_cert

# Decrypt signed message via verify method
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,              # in bytes
            message,                # M2
            padding.PSS(            # padding is PSS as server use PSS to sign msg
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

logging.basicConfig(filename='server_cp1.log', level=logging.INFO)

def log_resource_usage():
    process = psutil.Process(os.getpid())
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = process.memory_info().rss / 1024 / 1024  # in MB
    num_threads = process.num_threads()
    logging.info(f"CPU Usage: {cpu_usage}%")
    logging.info(f"Memory Usage: {memory_usage}MB")
    logging.info(f"Number of Threads: {num_threads}")

def encrypt_data(public_key, data):
    chunk_size = 117                #  Max block size for PKCS1v15 with 1024-bit key
    # concatenate encrypted blocks into a single byte array
    encrypted_chunks = bytearray()
    
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        # client use server public key, to ensure only server with private key can decrypt the data
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.PKCS1v15()
        )
        encrypted_chunks.extend(encrypted_chunk)
        
    return bytes(encrypted_chunks)

def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    ca_cert = load_certificates()

    print("Establishing connection to server...")
    #connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        # Upon successful connection
        auth_message = "authenticate me".encode('utf-8')  # M2 
        
        # MODE= 3 -- Handshake
        # send to server
        s.sendall(convert_int_to_bytes(3)) 
        s.sendall(convert_int_to_bytes(len(auth_message)))      # send M1 to server
        s.sendall(auth_message)                                 # send M2 to server

        # Receive signed message
        signed_auth_message_size = convert_bytes_to_int(read_bytes(s, 8))
        server_auth_message = read_bytes(s, signed_auth_message_size)

        server_signed_cert_size = convert_bytes_to_int(read_bytes(s, 8))
        server_signed_cert = read_bytes(s, server_signed_cert_size)
       
        signed_server_cert = x509.load_pem_x509_certificate(
            data=server_signed_cert, backend=default_backend()
        )

        # CHECK SERVER ID
        # 1. Extract public key, Kca+, from  csertificate.crt 
        try:
            ca_cert.public_key().verify(
                # 2. verify server certificate using Kca+
                signature=signed_server_cert.signature,                      # signature bytes to verify
                data=signed_server_cert.tbs_certificate_bytes,               # certificate data bytes that was signed by CA
                padding=padding.PKCS1v15(),                                  # padding used by CA bot to sign the server's csr
                algorithm=signed_server_cert.signature_hash_algorithm,
            )
            print("Server certificate verified successfully.")

        except InvalidSignature:
            print("Server certificate verification failed. Ensure the server's certificate is signed by a trusted CA.")
            s.sendall(convert_int_to_bytes(2))
            return

        # 3. Extract server's public key  Ks+ from server cert
        server_public_key = signed_server_cert.public_key()

        ''' Client confirms server is live by verifying the signed message and the 
            validity of the server's certificate using the server's public key '''
        
        # 4. Decrypt signed message via verify method
        if not verify_signature(server_public_key, auth_message, server_auth_message):
            print("Error: Server verification failed. Ensure the server is using the correct private key. Closing connection...")
            s.sendall(convert_int_to_bytes(2))                           # Mode=2
            return
        
        # Generate a secure random token aka nonce
        token = secrets.token_hex(16)  # Generates a 32-character hexadecimal token
        print(f"Live server verified successfully via the token: {token}")
        print("Authentication successful")  

        ''' MODE = 4
            Key generation '''
        # generate random key
        fernet_key = Fernet.generate_key()
        # make fernet object
        fernet = Fernet(fernet_key)
        encrypted_fernet_key = server_public_key.encrypt(
            fernet_key,
            padding.PKCS1v15()
        )
        s.sendall(convert_int_to_bytes(4)) 
        s.sendall(convert_int_to_bytes(len(encrypted_fernet_key)))      # send M1 to server
        s.sendall(encrypted_fernet_key)                                 # send M2 to server

        while True:
            filename = input("Enter a filename to send (enter -1 to exit):").strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename to the server
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                encrypted_data = fernet.encrypt(data)

                enc_filename = "enc_" + filename.split("/")[-1]
                # Write the file with 'send_files_enc' prefix
                with open(
                    f"send_files_enc/{enc_filename}", mode="wb"
                ) as fp:
                    fp.write(encrypted_data)
                print(
                    f"Encrypted file saved as send_files_enc/{enc_filename}"
                )                
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(encrypted_data)))
                s.sendall(encrypted_data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Client Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
