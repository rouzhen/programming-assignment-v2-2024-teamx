# 50.005 Programming Assignment 2

Authors:

- Xavier Tan
- Koo Rou Zhen

## Secure File Transfer

This project implements a secure file transfer protocol using public key cryptography to ensure the confidentiality and integrity of the transferred files. The protocol involves a client and a server, where the client encrypts the file data before sending it to the server, and the server decrypts the received data.

## Running the code

### Install required modules

This assignment requires Python >3.10 to run.

You can use `pipenv` to create a new virtual environment and install your modules there. If you don't have it, simply install using pip, (assuming your python is aliased as python3):

```
python3 -m pip install pipenv
```

Then start the virtual environment, upgrade pip, and install the required modules:

```
pipenv shell
python -m ensurepip --upgrade
pip install -r requirements.txt
```

# **Protocol Implementation**

## Key Features

1. **Public Key Cryptography**:

   - Client encrypts file data using the server's public key.
   - Server decrypts received data using its private key.

2. **File Content Encryption**:

   - Only the file content is encrypted; filenames remain unencrypted.
   - Encryption is performed in blocks to handle files of any size.

3. **RSA Padding**:

   - Uses PKCS1v15 padding for compatibility and efficiency.

4. **PSS Padding**:

   - Server uses PSS padding
     - for stronger security guarantees (under RSA assumption)
     - for randomization in padding process, ensures signed message produces different signatures every time

5. **Protocol Structure**:
   - Maintains the original protocol structure with MODEs 0, 1, 2, and 3.
   - MODE `3`: Authentication handshake
   - MODE `4`: Key Generation
   - MODE `0`: Filename
   - MODE `1`: File Data Block
   - MODE `2`: Connection closure

## Protocol

0. ### MODE `0` File Data Block:

- The client sends the filename to the server.
- The server receives and processes the filename

1. ### MODE `1` File Transfer:

- The client encrypts the file data using the symmetric key.
- The client sends the encrypted file data to the server.
- The server decrypts the received file data using the symmetric key.

2. ### MODE `2` Close Connection:

- The client sends a close connection request to the server.
- The server acknowledges the request and closes the connection.
- Both client and server clean up any resources and terminate the session.

3. ### MODE `3` Authentication Handshake:

- The client sends a connection request to the server.
- The server accepts the connection and sends an acknowledgment.
- The client sends an authentication request message to the server.
- The server responds with a signed authentication message and its signed certificate.
- The client verifies the server's signed certificate and the signed message using CA's public key `Kca+`.

4. ### MODE `4` Key Generation:

- The client generates a random symmetric key (Fernet key).
- The client encrypts the symmetric key using the server's public key `Ks-` and sends it to the server.
- The server decrypts the encrypted symmetric key using server's private key `Ks+`

## **Implementation Details**

## Client

The client script is `clientWithSecurityAP.py`, `clientWithSecurityCP1.py`, `clientWithSecurityCP2.py`.

#### `clientWithSecurityAP.py` handles the following tasks:

- The client sends an authentication request message to the server.

#### `clientWithSecurityCP1.py` handles the following tasks: (addding on to `clientWithSecurityAP.py`)

- Client encrypts the file data using the server's public key.
- Client sends the encrypted file data to the server.

#### `clientWithSecurityCP2.py` handles the following tasks: (addding on to `clientWithSecurityCP1.py`)

- Client generates a symmetric key using Fernet.
- Client encrypts the file data using the generated symmetric key.
- Client encrypts the symmetric key using the server's public key (RSA).
- Client sends the encrypted symmetric key to the server.
- Client sends the encrypted file data to the server.

### Running the Client

- To run the client, execute the following command:
  `python clientWithSecurity[AP/CP1/CP2].py`

## Server

The server scripts are `serverWithSecurityAP.py`, `serverWithSecurityCP1.py`, `serverWithSecurityCP2.py`.

#### `serverWithSecurityAP.py` handles the following tasks:

- The server responds with a signed authentication message and its signed certificate.

#### `serverWithSecurityCP1.py` handles the following tasks: (addding on to `serverWithSecurityAP.py`)

- Server decrypts the file data using its private key.

#### `serverWithSecurityCP2.py` handles the following tasks: (addding on to `serverWithSecurityCP1.py`)

- Server decrypts the symmetric key using its private key.
- Server decrypts the file data using the decrypted symmetric key.

### Running the Server

- To run the server, execute the following command:
  `python serverWithSecurity[AP/CP1/CP2].py`

## **Functions**

### Client

- `convert_int_to_bytes(x)` : Converts an integer to an 8-byte representation.
- `convert_bytes_to_int(xbytes)` : Converts a byte value to an integer.
- `read_bytes(socket, length)` : Reads the specified length of bytes from the given socket.
- `load_certificates()` : Loads the CA's certificate.
- `verify_signature(public_key, message, signature)` : Verifies a signature using the public key.
- `encrypt_data(public_key, data)` : Encrypts data using the public key.

### Server

- `convert_int_to_bytes(x)` : Converts an integer to an 8-byte representation.
- `convert_bytes_to_int(xbytes)` : Converts a byte value to an integer.
- `read_bytes(socket, length)` : Reads the specified length of bytes from the given socket.
- `load_keys_and_cert()` : Loads the server's private key and certificate.
- `sign_message(private_key, message)` : Signs a message using the server's private key.

### Ensure you have the necessary certificates and keys:

- `source/auth/server_private_key.pem` : Server's private key
- `source/auth/server_signed.crt` : Server's signed certificate
- `source/auth/cacsertificate.crt` : CA's certificate

# **Inclusivity Ideas**
1. ### Clear and Inclusive Documentation in README
-  #### **Detailed Instructions**:
   - The README explains includes step-by-step instructions for running the code, installing required modules, and setting up the environment.
-  #### **Clear Explanations**:
   - The README explains the key features, protocol structure, and implementation details of the project in a clear and detailed manner.
   - Covers both client and server functionalities, explaining their roles and the steps involved in the secure file transfer process
   
2. ### User-Friendly Error Messages:
-  #### **File Not Found**:
   - If the required keys or certificates are missing, the server will alert the user with a detailed message specifying which file is missing and suggesting to ensure the file exists in the source/auth/ directory.
   - `Error: [Errno 2] No such file or directory: 'source/auth/_private_key.pem'. Ensure the required files exist in 'source/auth/'.`
     
-  #### **Certificate Verification Failure**:
   - When the server's certificate cannot be verified using the CA's public key, the client will provide a clear message indicating the failure and closing the connection to prevent further insecure communication.
   - `Server certificate verification failed. Closing connection...`
     
-  #### **Invalid Signature**:
   - If the signature on a message cannot be verified, the client will inform the user about the failure and halt the authentication process.
   - `Server verification failed. Closing connection...`

-  #### **Socket Connection Issues**:
   -  If the socket connection is broken or if data cannot be read as expected, the server and client will raise an exception with a message indicating a broken connection.
   - `Exception: Socket connection broken`

-  #### **Invalid Filename**:
   -  If the user inputs an invalid filename when prompted, the client will prompt the user to re-enter a valid filename.
   - `Invalid filename. Please try again:`
          

# **Sustainability Ideas**
1. ### **Logging and Monitoring**:
   - Logged CPU usage, memory usage, and number of threads, to track resource usage during file transfers.
   - Example: `cpu_usage = psutil.cpu_percent(interval=1)` for CPU usage.
     
2. ### **Efficient Coding Practices**
In this project, we've implemented several efficient coding practices to ensure optimal performance and maintainability:

-  #### **Chunked File Processing**:

   - We process files in chunks rather than loading entire files into memory. This allows handling of large files without excessive memory usage.
   - Example: `chunk = data[i:i+chunk_size]` in the encryption function.

-  #### **Reusable Functions**:

   - Common operations are encapsulated in functions to promote code reuse and readability.
   - Example: `convert_int_to_bytes()` and `convert_bytes_to_int()` functions.

- #### **Consistent Error Handling**:

   - We use try-except blocks to handle potential errors, ensuring graceful failure and clear error messages.
   - Example: `except InvalidSignature:` in the certificate verification process.

- #### **Use of Context Managers**:

   - We use `with` statements for file and socket operations to ensure proper resource management.
   - Example: `with open(filename, mode="rb") as fp:` for file operations.

- #### **Efficient Data Structures**:
   - We use bytearray for building decrypted data, which is more efficient for repeated concatenations than strings or bytes.
   - Example: `decrypted_file_data = bytearray()` in the server's decryption process.

We encourage contributors to follow these practices in future development to maintain code quality and performance.
