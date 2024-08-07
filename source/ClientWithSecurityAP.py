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
        ca_cert = x509.load_pem_x509_certificate( data= cert_file.read(), backend= default_backend())
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



def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    ca_cert = load_certificates()

    print("Establishing connection to server...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        auth_message = "authenticate me".encode('utf-8')
        
        s.sendall(convert_int_to_bytes(3))
        s.sendall(convert_int_to_bytes(len(auth_message)))
        s.sendall(auth_message)

        auth_message_size = convert_bytes_to_int(read_bytes(s, 8))
        server_auth_message = read_bytes(s, auth_message_size)

        server_signed_cert_size = convert_bytes_to_int(read_bytes(s, 8))
        server_signed_cert = read_bytes(s, server_signed_cert_size)

        # Load server certificate
        server_cert = x509.load_pem_x509_certificate(server_signed_cert, default_backend())

        # Verify the server's certificate using the CA certificate
        try:
            ca_cert.public_key().verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                server_cert.signature_hash_algorithm,
            )
            print("Server certificate verified successfully.")
        except InvalidSignature:
            print("Server certificate verification failed.")
            s.sendall(convert_int_to_bytes(2))
            return

        # Extract server's public key from the verified certificate
        server_public_key = server_cert.public_key()


        ''' Client confirms server is live by verifying the signed message and the 
            validity of the server's certificate using the server's public key '''
        
        # 4. Decrypt signed message via verify method
        if not verify_signature(server_public_key, auth_message, server_auth_message):
            print("Server verification failed. Closing connection...")
            s.sendall(convert_int_to_bytes(2))              # Mode=2
            return

        # Generate a secure random token aka nonce
        token = secrets.token_hex(16)  # Generates a 32-character hexadecimal token
        print(f"Live server verified successfully via the token: {token}")
        print("Authentication successful")  

        while True:
            filename = input("Enter a filename to send (enter -1 to exit):").strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)


            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))
                s.sendall(data)

        s.sendall(convert_int_to_bytes(2))
        log_resource_usage()
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
