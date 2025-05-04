import socket
from Crypto.Cipher import AES
import time
import os
import bcrypt

    #Klucz do szyfrowania AES
key = b'tomaszjarzabekke'

    #Funkcja szyfrująca wiadomość, zwraca sól oraz zaszyfrowaną w AES wiadomość (strumień bitów)
def encipher(message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    #ciphertext = ciphertext.encrypt(message)
    ciphertext = cipher.encrypt(message)
    return nonce, ciphertext

    #Funkcja haszująca hasło użytkownika, nie możemy go rpzechowywać w formie podstawowej
def hash_password_bcrypt(password):
    # Generuj sól (możesz ją przechowywać w bazie danych)
    salt = b'$2b$12$rjHEhNIX82YQxvU4pN6bIu'
    # Haszuj hasło za pomocą bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

    #Funkcja wysyłająca do serwera jego nazwę, nazwę pliku, rozmiar oraz hasło użytkownika
def send_user_filename_size(username, temp_filename, filesize, passcode):
    data = f"{username};{temp_filename};{filesize};{passcode}"
    return data

username = input('Welcome to tomek\'s program, input your username:')
passwd = input('Welcome to tomek\'s program, input your password:')

    #Rozpoczęcie łączenia z serwerem
while True:
    s = socket.socket()
    port = 40444
    s.connect(('127.0.0.1', port))
    usename = username
    password = passwd
        #Tutaj wskazuje się na ścieżkę pliku
    file_path = r"sendfile.txt"
    filename = os.path.basename(file_path)
    filesize = str(os.path.getsize(file_path))
        #Dla debugingu, printujemy te zmienne
    print(usename)
    print(filename)
    print(filesize)
    print(hash_password_bcrypt(password))
    s.sendall(send_user_filename_size(usename,filename,filesize,hash_password_bcrypt(password)).encode())

    with open(file_path, 'rb') as file:
        while True:
            data = file.read()
            if not data:
                break
            print(data)
            nonce, ciphertext = encipher(data)
            #Dla debugingu, printujemy zaszyfrowaną wiadomość i sól przesłane
            print(f'nciphetedxt: {ciphertext}')
            print(f'nonce: {nonce}')
            s.send(nonce)
            s.send(ciphertext)
    s.close()
    time.sleep(10)
