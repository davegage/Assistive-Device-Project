#!/usr/bin/python3

from socket import *
import ssl
import socket
import time


host_addr = '127.0.0.1'
host_port = 80
server_sni_hostname = 'example.com'
server_cert = 'server.crt'
client_cert = 'client.crt'
client_key = 'client.key'

isAuth = False

def Authorize():
    global isAuth
    isAuth = True

def resetAuthorization():
    global isAuth
    isAuth = False


context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
context.load_cert_chain(certfile=client_cert, keyfile=client_key)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = context.wrap_socket(s, server_side=False, server_hostname=server_sni_hostname)
conn.connect((host_addr, host_port))
print("SSL established. Peer: {}".format(conn.getpeercert()))
while True:
        if(isAuth != True):
            print("hi")
            #perform Speech to text password request
            Authorize()
        elif(isAuth == True):
            print ("\n input GET bookname to get book content;        \
                \n input q to exit")
            command = raw_input()
            httpMethod = command.split(" ")[0]
            if httpMethod == "GET":

                filename = command.split(" ")[1]
                #print (" filename: ", filename)

                # Generate GET message
                getMessage = "GET " + filename

                conn.sendall(getMessage.encode())
                time.sleep(1)

                #Fill in start
                # message received from server
                result = conn.recv(4096)
                #Fill in end

                # here it would be the request file's content
                print('Received from the server :', (result.decode('utf-8')))
            elif(httpMethod == 'q'):
                getMessage = 'q'
                conn.sendall(getMessage.encode())
                resetAuthorization()
                break

    #Fill in start
    # close the connection
conn.close()

    #Fill in end
conn.close()