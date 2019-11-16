#import socket module
from socket import *
import socket

# import thread module
from threading import Lock
from thread import *

# import path
from os import path

plock = Lock()

# initialize IP and Port number
host = ""
port = 80

# thread fuction
def threadOperation(connectionSocket):
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
        data = connectionSocket.recv(1024)
        data = (data.decode('ascii'))

        # Split http field
        httpMethod = data.split(" ")[0]

        # Checks if HTTP command is GET
        if httpMethod == "GET":

            # Splits the filename field
            filename = data.split(" ")[1]

            # Checks if file exists
            if path.exists("./"+filename+".txt"):

                # If so, read content from file and send back to client with HTTP response
                file = open("./"+filename+".txt", 'r')
                content = file.read()

                print("Received request from a client: " + content)
                getMessage = ("Book Content:u " + content)

                connectionSocket.sendall(content)
                file.close()

                # If file doesn't exist send 404 Not Found Error
            else:
                getMessage = "Book does not exist"
                connectionSocket.sendall(getMessage.encode())
        elif(httpMethod == "q"):
            break;


def executeFunction(connectionSocket):
    '''
    start a new thread function
    '''
    # lock acquired by client
    plock.acquire()

    # Fill in start
    # Start a new thread using Thread library, the thread function is threadOperation above
    start_new_thread(threadOperation, (connectionSocket,))
    # Fill in end

    print("new_thread done. ")


def serverExecute():
    '''
    main entry function for a server
    '''
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Prepare a sever socket
    # Fill in start
    # bind the socket to a public host, and a well-known port
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((host,port))
    # Fill in end

    # become a server socket and in listening mode
    serverSocket.listen(5)

    while True:
        print("Ready to serve...")
        # Establish the connection
        connectionSocket, addr = serverSocket.accept()
        executeFunction(connectionSocket)

    # Fill in start
    # Close client socket
    clientSocket.close()
    # Fill in end
    serverSocket.close()


serverExecute()
