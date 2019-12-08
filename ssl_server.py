#!/usr/bin/python3

import socket
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
import ssl
import OpenSSL
# import thread module
from threading import Lock
from _thread import *
from os import path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
import base64
import bcrypt

listen_addr = ""
listen_port = 80
server_cert = 'server.crt'
server_key = 'server.key'
client_certs = 'client.crt'
symmetric_key = ""
f = ""

hasKey = False
isAuth = False

plock = Lock()

with open("server.key", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
def key():
    global hasKey
    hasKey = True
def resetKey():
    global hasKey
    hasKey = False

def Authorize():
    global isAuth
    isAuth = True
def resetAuthorize():
    global isAuth
    isAuth = False


def check_password(plain_text_password):
    with open('./password.pwd') as f:
        first_line = f.readline()
        first_line = first_line.encode('utf-8')
        plain_text_password = plain_text_password.encode('utf-8')
        return bcrypt.checkpw(plain_text_password, first_line)


def save_password(plain_text_password):
    f = open('./password.pwd', "w")
    f.write(bcrypt.hashpw(plain_text_password, bcrypt.gensalt()))
    f.close()

def threadOperation(conn):
    global symmetric_key
    global hasKey
    global f
    # Receive client message
    while True:
        if (hasKey != True):
            data = conn.recv(1024)
            data = (data.decode('ascii'))
            print("Encrypted Symmetric Key: "+str(data))
            decode_cipher = base64.b64decode(data)
            plain = private_key.decrypt(decode_cipher, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
            plaintext_key = plain.decode('utf-8')
            symmetric_key = plaintext_key
            print("Symmetric Key: "+symmetric_key+"\n")
            f = Fernet(symmetric_key)
            #print(f)
            key()
        elif (hasKey == True):
            if (isAuth != True):
                data = conn.recv(1024)
                data = (data.decode('ascii'))
                data = data.encode('utf-8')
                print("Client's Encrypted Hash Password " + str(data))
                encrypted_hash_pass = f.decrypt(data)
                hash_pass = encrypted_hash_pass.decode('utf-8')
                print("Client's Decrypted Hash Password: " + hash_pass)
                #hash_pass = hash_pass.encode('utf-8')
                print(hash_pass)
                if check_password(hash_pass):
                    print("Successful")
                    sendMessage = "Correct"
                    print("Server's Message: " + sendMessage)
                    content = sendMessage.encode("ascii", "ignore")
                    encode_cipher = f.encrypt(content)
                    print("Server's Encrypted Message: " + str(encode_cipher))
                    conn.sendall(encode_cipher)
                    Authorize()
                else:
                    sendMessage = "Incorrect"
                    print("Server's Message: " + sendMessage)
                    content = sendMessage.encode("ascii", "ignore")
                    encode_cipher = f.encrypt(content)
                    print("Server's Encrypted Message: " + str(encode_cipher))
                    conn.sendall(encode_cipher)
            elif (isAuth == True):
                data = conn.recv(1024)
                data = (data.decode('ascii'))
                data = data.encode('utf-8')
                print("Client's Encrypted Request " +str(data))

                #Decrypts Client's Request
                plaintext = f.decrypt(data)
                plaintext = plaintext.decode('utf-8')
                print("Client's Decrypted Request: " + plaintext)

                request = plaintext.split(" ")[0]
                # Checks request
                if request == "read":

                    # Splits the filename field
                    filename = plaintext.split(" ")[1]
                    chapter = plaintext.split(" ")[2]
                    # Checks if file exists
                    if path.exists("./"+filename+" "+chapter+".txt"):

                        # If so, read content from file and send back to client
                        file = open("./"+filename+" "+chapter+".txt", 'r')
                        cont = file.read()

                        getMessage = ("Server's Message: " + cont)
                        print(getMessage)
                        content = cont.encode("ascii", "ignore")
                        #mes = content.encode('utf-8')
                        encode_cipher = f.encrypt(content)
                        print("Server's Encrypted Message: "+str(encode_cipher))
                        conn.sendall(encode_cipher)
                        file.close()

                        # If file doesn't exist send 404 Not Found Error
                    else:
                        getMessage = "The Book does not exist, please try again"
                        print("Server's Message: "+getMessage)
                        content = getMessage.encode("ascii", "ignore")
                        encode_cipher = f.encrypt(content)
                        print("Server's Encrypted Message: "+str(encode_cipher))
                        conn.sendall(encode_cipher)
                elif(request == "q"):
                    break;


def executeFunction(conn):
    # lock acquired by client
    plock.acquire()

    # Fill in start
    # Start a new thread using Thread library, the thread function is threadOperation above
    start_new_thread(threadOperation, (conn,))
    # Fill in end

    print("new_thread done. ")

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=server_cert, keyfile=server_key)

bindsocket = socket.socket()
bindsocket.bind((listen_addr, listen_port))
bindsocket.listen(5)

while True:
    print("Waiting for client")
    newsocket, fromaddr = bindsocket.accept()
    print("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
    conn = context.wrap_socket(newsocket, server_side=True)
    print("SSL established. Peer: {}".format(conn.getpeercert()))
    executeFunction(conn)

print("Closing connection")
conn.shutdown(socket.SHUT_RDWR)
conn.close()