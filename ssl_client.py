#!/usr/bin/python3

from socket import *
import ssl
import socket
import os
import time
import speech_recognition as sr
from gtts import gTTS
import playsound


host_addr = '127.0.0.1'
host_port = 80
server_sni_hostname = 'example.com'
server_cert = 'server.crt'
client_cert = 'client.crt'
client_key = 'client.key'

r = sr.Recognizer()
isAuth = False
i = 0

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
            with sr.Microphone() as source:
                print ("\n input read bookname to get book content;        \
                    \n input quit to exit")
                tts = gTTS(text="Hello welcome to voice assistant book reader, please make a request to read a book")
                filename = "hello.mp3"
                playsound.playsound(filename)
                audio = r.listen(source)
                text = ""
                try:
                    text = r.recognize_google(audio)
                    command = format(text)
                    print('You said: ' + command)
                    # command = input()
                    request = command.split(" ")[0]
                    if request == "read":

                        filename = command.split(" ")[1]
                        chapter = command.split(" ")[2]


                        # Generate read message
                        sendMessage = "read "+filename+" "+chapter

                        conn.sendall(sendMessage.encode())
                        time.sleep(1)

                        # Fill in start
                        # message received from server
                        result = str(conn.recv(4096).decode('utf-8'))
                        # Fill in end

                        print('Received from the server :', result)
                        tts = gTTS(text=result)

                        filename = "book"+str(i)+".mp3"
                        tts.save(filename)
                        playsound.playsound(filename)
                        os.remove(filename)
                        i = i + 1
                    if request == 'quit':
                        sendMessage = 'quit'
                        conn.sendall(sendMessage.encode())
                        resetAuthorization()

                        tts = gTTS(text="Good bye")
                        filename = "goodbye.mp3"
                        playsound.playsound(filename)
                        break
                    elif request != "read":
                        tts = gTTS(text="Could not process your request, please repeat again")
                        filename = "error.mp3"
                        playsound.playsound(filename)
                except Exception as e:
                    print("Exception: "+str(e))


    #Fill in start
    # close the connection
conn.close()

    #Fill in end
conn.close()