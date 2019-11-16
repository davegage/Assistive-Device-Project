#import socket module
from socket import *
import time
import socket

port = 80
host = '127.0.0.1'

isAuth = False

def Authorize():
    global isAuth
    isAuth = True

def resetAuthorization():
    global isAuth
    isAuth = False

def clientExecute():
    '''
    main entry function for a client
    '''
    print("hii")
    #create an INET, STREAMing socket
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #Fill in start
    #prepare a client socket
    clientSocket.connect((host,port))
    #Fill in end

    while True:
        if(isAuth != True):
            print("hi")
            #perform Speech to text password request
            Authorize()
        elif(isAuth == True):
            print ("\n input GET bookname to get book content;        \
                \n input q to exit")
            command = input()
            httpMethod = command.split(" ")[0]
            #print (" httpMethod: ", httpMethod)
            if httpMethod == "GET":

                filename = command.split(" ")[1]
                #print (" filename: ", filename)

                # Generate GET message
                getMessage = "GET /" + filename + " HTTP/1.1\r\nHost: localhost:6789\r\n\r\n"

                clientSocket.sendall(getMessage.encode())
                time.sleep(1)

                #Fill in start
                # message received from server
                result = clientSocket.recv(4096)
                #Fill in end

                # here it would be the request file's content
                print('Received from the server :', str(result.decode('utf-8')))
            elif(httpMethod == 'q'):
                getMessage = 'q'
                clientSocket.sendall(getMessage.encode())
                resetAuthorization()
                break

    #Fill in start
    # close the connection
    clientSocket.close()

    #Fill in end

clientExecute()
