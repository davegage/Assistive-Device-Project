#!/usr/bin/python3

import socket
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
import ssl

# import thread module
from threading import Lock
from _thread import *

from os import path

listen_addr = ""
listen_port = 80
server_cert = 'server.crt'
server_key = 'server.key'
client_certs = 'client.crt'

plock = Lock()

def threadOperation(conn):
    '''
    Please implement this function. You might refer to the implementation: https://www.geeksforgeeks.org/socket-programming-multi-threading-python/
    This functions does the following work:

      (1)Keep receive message from client and parse the messsage header as GET or POST
      (2) Judge if it's GET and POST and act accordingly
      (3) If it's GET, it gets filename requested,
           (a)  if successfully reads a message from the client; then it will read the content from the file.
                and then reply back HTTP OK with the content together to the client
           (b) if not, it will reply HTTP 404 NOT FOUND to the client
      (4) If it's POST, it just will parse it and store it in a file, and then reply HTTP OK back to the client

    '''
    # Fill in start

    # Receive client message
    while True:
        data = conn.recv(1024)
        data = (data.decode('ascii'))
        print(data)
        # Split http field
        httpMethod = data.split(" ")[0]

        # Checks if HTTP command is GET
        if httpMethod == "GET":

            # Splits the filename field
            filename = data.split(" ")[1]

            # Checks if file exists
            if path.exists("./"+filename):

                # If so, read content from file and send back to client with HTTP response
                file = open("./"+filename, 'r')
                content = file.read()

                print("Received request from a client: " + content)
                getMessage = ("Book Content:u " + content)

                conn.sendall(content.encode())
                file.close()

                # If file doesn't exist send 404 Not Found Error
            else:
                getMessage = "Book does not exist"
                conn.sendall(getMessage.encode())
        elif(httpMethod == "q"):
            break;


def executeFunction(conn):
    '''
    start a new thread function
    '''
    # lock acquired by client
    plock.acquire()

    # Fill in start
    # Start a new thread using Thread library, the thread function is threadOperation above
    start_new_thread(threadOperation, (conn,))
    # Fill in end

    print("new_thread done. ")

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(certfile=server_cert, keyfile=server_key)
context.load_verify_locations(cafile=client_certs)

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