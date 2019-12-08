import base64
import ssl
import socket
import os
import time
import speech_recognition as sr
from gtts import gTTS
import playsound
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
import bcrypt

host_addr = '127.0.0.1'
host_port = 80
server_sni_hostname = 'example.com'
server_cert = 'server.crt'
server_pem = 'server.pem'

r = sr.Recognizer()
isAuth = False
hasKey = False
i = 0

#Function called to check if client is authorized
def Authorize():
    global isAuth
    isAuth = True
#Function to reset client authorization after client quits
def resetAuthorization():
    global isAuth
    isAuth = False
#Function to create symmetric key
def createKey():
    key = Fernet.generate_key()
    return key
#Function to check if client & server have the same symmetric key
def key():
    global hasKey
    hasKey = True
#Function to reset symmetric key after client quits
def resetkey():
    global hasKey
    hasKey = False


def get_hashed_password(plain_text_password):
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())

#Server Authentication
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = context.wrap_socket(s, server_side=False, server_hostname=server_sni_hostname)
conn.connect((host_addr, host_port))

#print("SSL established. Peer: {}".format(conn.getpeercert()))

#Extracts Server's Public Key
server_cert = open('server.crt').read()
#print(server_cert)
cert = x509.load_pem_x509_certificate(str.encode(server_cert), default_backend())
cert_pub = cert.public_key()
#print(cert_pub)

# RSA Encrypting and Decrypting Testing
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
with open("server.key", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )     
#Public Key
server_cert = open('server.crt').read()
print(server_cert)
cert = x509.load_pem_x509_certificate(str.encode(server_cert), default_backend())
cert_pub = cert.public_key()
print(cert_pub)
message = "TeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeHEEEEEEEEEEEEEEEEEEEEEEEEEE"
mes = message.encode('utf-8')
cipher = cert_pub.encrypt(mes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
print("Cipher: " +str(cipher))
encode_cipher = base64.b64encode(cipher)
print("Cipher: " +str(encode_cipher))
decode_cipher = base64.b64decode(encode_cipher)
plaintext = private_key.decrypt(decode_cipher, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
print("Plaintext: "+str(plaintext.decode('utf-8')))
"""
while True:
    if(hasKey != True):
        #Create Symmetric Key Here
        symmetric_key = createKey()
        print("Symmetric Key: "+str(symmetric_key))
        cipher = cert_pub.encrypt(symmetric_key,
                                  padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                               algorithm=hashes.SHA256(),
                                               label=None))
        encode_cipher = base64.b64encode(cipher)
        print("Encrypted Symmetric Key: "+str(encode_cipher)+"\n")
        conn.sendall(encode_cipher)
        f = Fernet(symmetric_key)
        #print(f)
        key()
    elif(hasKey == True):
        if(isAuth != True):
            print("Checking if Client is Authorized")
            #perform Speech to text password request
            with sr.Microphone() as source:
                print("\n input your password;        \
                                    \n")
                tts = gTTS(text="Please enter your password")
                filename = "password_request.mp3"
                playsound.playsound(filename)
                audio = r.listen(source)
                text = ""
                try:
                    print("hi")
                    text = r.recognize_google(audio)
                    command = format(text)
                    print("Password:" +command)
                    command = command.encode('utf-8')
                    print("Encoded Password: " +str(command))
                    mes = command
                    encode_cipher = f.encrypt(mes)
                    print("Encrypted Hash Password:" + str(encode_cipher))
                    conn.sendall(encode_cipher)

                    result = str(conn.recv(4096).decode('utf-8'))
                    print("Sever's Password Encrypted Result: "+result)
                    result = result.encode('utf-8')
                    result = f.decrypt(result)
                    result = result.decode('utf-8')
                    print("Server's Password Decrypted Result: ", result)
                    if result == "Correct":
                        Authorize()
                    elif result == "Incorrect":
                        tts = gTTS(text="The password you entered was incorrect, please try again")
                        filename = "incorrect_password.mp3"
                        playsound.playsound(filename)
                except Exception as e:
                    print("Exception: "+str(e))
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
                        mes = sendMessage.encode('utf-8')
                        encode_cipher = f.encrypt(mes)
                        print("Encrypted Request:" +str(encode_cipher))
                        conn.sendall(encode_cipher)
                        time.sleep(1)

                        # message received from server
                        result = str(conn.recv(4096).decode('utf-8'))
                        result = result.encode('utf-8')
                        print("Server's Encrypted Message: ", str(result))
                        result = f.decrypt(result)
                        result = result.decode('utf-8')
                        print("Server's Decrypted Message: ", result)

                        tts = gTTS(text=result)

                        filename = "book"+str(i)+".mp3"
                        tts.save(filename)
                        playsound.playsound(filename)
                        os.remove(filename)
                        i = i + 1
                    if request == 'quit':
                        sendMessage = "q"
                        mes = sendMessage.encode('utf-8')
                        encode_cipher = f.encrypt(mes)
                        print("Encrypted Request:" + str(encode_cipher))
                        conn.sendall(encode_cipher)
                        resetkey()
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

    # close the connection
conn.close()
