import socket
from Crypto.Cipher import AES
import os
import time
import bcrypt

#Klucz potrzebny do dekrypcji
key = b'tomaszjarzabekke'


#Funkcja deszyfrująca nam przesłaną wiadomość
def decipher(nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        return plaintext
    except:
        return False

#Funkcja sprawdzająca z pliku users.txt użytkownika i jego hasło
def authorise(username, passcode):
    print("Username to jest:" + username)
    print("Username to jest:" + passcode)
    with open('users.txt', 'r') as userfile:
        allfile = userfile.readlines()
        for i in range(len(allfile)):
            userlist = allfile[i].strip()
            userspaswds= userlist.split(" ")
            if (userspaswds[0] == username):
                print(userspaswds[0] + "==" + username)
                print(userspaswds[1])
                print(passcode)
                if (userspaswds[1] == passcode):
                    print(userspaswds[1] + "==" + passcode)
                    userfile.close()
                    return 1
        userfile.close()

#Funkcja zwracająca czy użytkownik jest w bazie danych czy nie
def check_user(usename,password):
    if (authorise(usename,password) != 1):
        print("Unexpected username, aborting program")
        raise SystemExit
    else:
        print("Username recognised. Proceeding to decode message...")

#Jeśli jest i nie ma folderu, to go tworzymy
def create_folder(folder_path):
    try:
        os.mkdir(folder_path)
        print(f"Folder '{folder_path}' created successfully.")
    except FileExistsError:
        print(f"Folder '{folder_path}' already exists.")

#Sprawdzenie czy folder istnieje
def folder_exist(directory):
    if os.path.exists(directory):
        return 1
    else:
        return 0

#Determinujemy, czy użytkownik ma ścieżkę i jeśli tak, to jak ona wygląda
def determine_user_path(username):
    with open('users.txt', 'r') as userfile:
        allfile = userfile.readlines()
        for i in range(len(allfile)):
            userlist = allfile[i].strip()
            userspaswds = userlist.split(" ")
            if (userspaswds[0] == username):
                userfile.close()
                userpath=username
        userfile.close()
    if (folder_exist(userpath) == 1):
        return userpath
    else:
        create_folder(userpath)

#Zapisujemy otrzymaną wiadomość do pliku
def save_to_file(file,file_path,filename):
    file_path = os.path.join(file_path, filename)
    bytes_file=b''
    bytes_file += file
    if ((filename[:4] == ".txt") or (filename[:5] == ".docx")):
        file = file.decode()
        with open(file_path, 'w') as file_save:
            file_save.write(file)
    else:
        with open(file_path, 'wb') as file_save:
            file_save.write(file)

#Porównujemy strumień bitów starszej wiadomości z nowszą, używane do synchronizacji
def compare_files(file1, file2):
    if (file1 == file2):
        return 1
    else:
        return 0

s = socket.socket()
port = 40444
s.bind(('127.0.0.1', port))
print ('Socket binded to port: ', port)
s.listen(5)
print ('socket is listening')

plaintext_old=b''
buffer = b''

#Włączamy serwer
while True:
    c, addr = s.accept()
    print ('Got connection from ', addr)
        #Przyjmujemy wiadomość od klienta
    message = c.recv(2048)

    message = str(message.decode())
        #Dzielimy ją na konkretne zmienne
    usename, temp_filename, filesize, password = message.split(';')
        #Weryfikacja użytkownika
    check_user(usename,password)

    filesize = int(filesize)

    print(temp_filename)
    filename = temp_filename

    #Otrzymujemy plik/strumień bitów oraz sól
    data = c.recv(filesize)
    data2 = c.recv(filesize)

    nonce=data
    ciphertext = data2

        #Rozszyfrujemy wiadomość używając AES
    plaintext = decipher(nonce, ciphertext)
        #Jeśli nie przechowujemy starej wiadomości (program dopiero się zaczął), to zapisujemy go i przypisujemy starszej wersji teraźniejszą
    if plaintext_old == b'':
        plaintext_old = plaintext
        print("Nastapila zmiana plaintext_olda w pierszym przypadku")
        save_to_file(plaintext, determine_user_path(usename), filename)

    if not plaintext:
        print("Message corrupted!")
    else:
        print(f'Your message is: {plaintext}')

        #Jeśli starsza wersja nie równa sie nowszej, to zapisujemy ją i przypisujemy teraźniejszą do starszej
    if compare_files(plaintext,plaintext_old) == 0:
        print("Pliki sie roznia. Nastapila zmiana plaintext_olda w drugim przypadku")
        save_to_file(plaintext,determine_user_path(usename),filename)
        plaintext_old = plaintext

    filesize=0
        #Ostateczne sprawdzenie czy coś jeszcze przyadkiem, jakieś śmieci, nie zostały przeslane
    czycos=c.recv(1024)
    print(czycos)
    c.close()
    time.sleep(5)
