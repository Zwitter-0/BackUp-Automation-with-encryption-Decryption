"""
1. change paths in path function 
2. 
"""
from time import sleep
from cryptography.fernet import Fernet
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import shutil
import time
import sys
from datetime import datetime

from pydrive.drive import GoogleDrive 
from pydrive.auth import GoogleAuth 


"""
main encryption class
"""
class Encryptor():

    def key_create(self):
        key = Fernet.generate_key()
        return key

    def key_write(self, key, key_name):
        with open(key_name, 'wb') as mykey:
            mykey.write(key)

    def key_load(self, key_name):
        with open(key_name, 'rb') as mykey:
            key = mykey.read()
        return key


    def file_encrypt(self, key, original_file, encrypted_file):
        
        f = Fernet(key)

        with open(original_file, 'rb') as file:
            original = file.read()

        encrypted = f.encrypt(original)

        with open (encrypted_file, 'wb') as file:
            file.write(encrypted)

    def file_decrypt(self, key, encrypted_file, decrypted_file):
        
        f = Fernet(key)

        with open(encrypted_file, 'rb') as file:
            encrypted = file.read()

        decrypted = f.decrypt(encrypted)

        with open(decrypted_file, 'wb') as file:
            file.write(decrypted)

# returns the paths to move files and save files
def get_path(path_name):
    if path_name == "encrption folder":
        path2 = os.getcwd()

        path2 = "PATH TO ENCRYPTION FOLDER"
        try:
            os.chdir(path2)
        except FileNotFoundError:
            print("Directory: {0} does not exist".format(path2))
        except NotADirectoryError:
            print("{0} is not a directory".format(path2))
        except PermissionError:
            print("You do not have permissions to change to {0}".format(path2))
        print("returning encryption folder path {}".format(path2))
        return path2
    elif path_name == "decryption folder":
        path2 = "PATH TO DECRYPTION FOLDER"
        try:
            os.chdir(path2)
        except FileNotFoundError:
            print("Directory: {0} does not exist".format(path2))
        except NotADirectoryError:
            print("{0} is not a directory".format(path2))
        except PermissionError:
            print("You do not have permissions to change to {0}".format(path2))
        print("returning decryption folder path {}".format(path2))
        return path2
    elif path_name == "backup folder":
        path2 = "PATH TO BACKUP FOLDER"
        try:
            os.chdir(path2)
        except FileNotFoundError:
            print("Directory: {0} does not exist".format(path2))
        except NotADirectoryError:
            print("{0} is not a directory".format(path2))
        except PermissionError:
            print("You do not have permissions to change to {0}".format(path2))
        print("returning bacup folder path {}".format(path2))
        return path2
    else:
        path2 = "PATH TO BACUP FOLDER"
        try:
            os.chdir(path2)
        except FileNotFoundError:
            print("Directory: {0} does not exist".format(path2))
        except NotADirectoryError:
            print("{0} is not a directory".format(path2))
        except PermissionError:
            print("You do not have permissions to change to {0}".format(path2))
        print("returning main folder path {}".format(path2))
        return path2     

def key_enc(data_):
    # get the plaintext
    data = data_
    output_file = 'PATH TO KEY FOR ECNRPTION AND DECRYPTION' # Output file
    key = b'YOUR KEY is keys' # The key you generated
    print(type(data))
    # Create cipher object and encrypt the data
    cipher = AES.new(key, AES.MODE_CBC) # Create a AES cipher object with the key using the mode CBC
    ciphered_data = cipher.encrypt(pad(data, AES.block_size)) # Pad the input data and then encrypt
    print(ciphered_data)
    file_out = open(output_file, "wb")
    file_out.write(cipher.iv)
    file_out.write(ciphered_data)
    file_out.close()

def get_key():
    path = get_path('ma')
    path = ("{}mykey.key").format(path)
    print(path)
    key = b'YOUR KEY is keys' # The key you generated
    input_file = 'mykey.key' # Input file
    # Read the data from the file
    file_in = open(input_file, 'rb') # Open the file to read bytes
    iv = file_in.read(16) # Read the iv out - this is 16 bytes long
    ciphered_data = file_in.read() # Read the rest of the data
    file_in.close()
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)  # Setup cipher
    original_data = unpad(cipher.decrypt(ciphered_data), AES.block_size) # Decrypt and then 
    return original_data

# print menu
def menu():
    cho = input("[*] 1. Encrypt Files.\n[*] 2. Decrypt Files\n")
    print(cho)
    while (cho != '1' and cho != '2'):
        print("input 1 or 2  .....!")
        cho = input("[*] 1. Encrypt Files.\n[*] 2. Decrypt Files\n")
    cho = int(cho)
    print("returning menu result {}".format(cho))
    print(type(cho))
    print("\n\n")
    return cho

# give all the files in given directory in list
def Files(path):
    files = []
    files = os.listdir(path)
    print("returning this files list {}".format(files))
    return files

# move files between folder
def Move_files(source , destination , file):
        
    """
    Saving data in files
    """
    if file == "enc_":
        source_ = "{}/".format(source)
        #C:\Users\chhus\Desktop\work\pending\obaidAslam\encryption folder
        destination = "{}/encrypted/".format(source_)
        files = Files(get_path("ma"))
        for f in files:
            print(f)
            if f.startswith('enc_'):
                sleep(3)
                print("{} moved".format(f))
                shutil.move(os.path.join(source, f), os.path.join(destination, f))
            else:
                print("{} pass".format(f))
                pass
    elif file == "dec_":
        source_ = "{}/".format(source)
        #C:\Users\chhus\Desktop\work\pending\obaidAslam\encryption folder
        destination = "{}/".format(destination)
        files = Files(get_path("encrption folder"))
        for f in files:
            print(f)
            if f.startswith('dec_'):
                sleep(1)
                print("{} moved".format(f))
                shutil.move(os.path.join(source, f), os.path.join(destination, f))
            else:
                print("{} pass".format(f))
                pass


# backup setup start.....

def create_zip(path_, file_name):
    try:
        print(file_name)
        file_name = file_name.replace(':','-')
        path= ("{}backup".format(path_))
        print(path)
        path2 = get_path("ma")
        print(path2)
        shutil.make_archive(f"{path2}archive/{file_name}", 'zip', path)
        return True
    except FileNotFoundError as e:
        return False

def google_auth():
    gauth = GoogleAuth() 
    gauth.LocalWebserverAuth()        
    drive = GoogleDrive(gauth) 
    return gauth, drive

def upload_backup(drive, path, file_name):
    f = drive.CreateFile({'title': file_name}) 
    f.SetContentFile(os.path.join(path, file_name)) 
    f.Upload() 
    f = None

def controller():
    path = r""
    now = datetime.now()
    file_name = "backup " + now.strftime(r"%d/%m/%Y %H:%M:%S").replace('/', '-')

    if  not create_zip(path, file_name):
        print("exiting program......")
        time.sleep(2)
        sys.exit(0)
    auth, drive = google_auth()
    file_name = file_name+'.zip'
    file_name = file_name.replace(':','-')
    print(file_name)
    path2= r""
    print(path2)
    lst = os.listdir(path2)
    for ele in lst:
        print(ele)
        print("file found: {} ".format(ele == file_name))
        if ele == file_name:
            print(file_name)
            upload_backup(drive,path2, file_name)




# backup setup ends......

def main():
    # file list to store all files
    files = [] 
    files = Files(get_path("ma"))
    encryptor=Encryptor()

    # key to check key generated or not 
    key = True
    for file in files:
        if file.endswith(".key"):
            key = False 
            print(file)
            print(key)
    print(key)

    # generate key if not generated yet.
    if (key):
        mykey=encryptor.key_create()
        key_enc(mykey)
        print(len(mykey))
        print(type(mykey))
        print(mykey)

    # variable to store key
    loaded_key=get_key()
    print("key loaded{}\n\n".format(loaded_key))
    # print menu
    choice = menu()
    sleep(3)
    # calling encryption function 
    if choice == 1:
        print("\nencrypting files.....!\n")
        print(files)
        for file in files:
            if file.endswith(".key") or file.endswith(".py") or file.startswith('encrypted') or file.startswith('decrypted') or file.endswith('.json') or file.startswith('archive') or file.startswith('backup') or file.startswith('bachuparchive') or file.endswith('.bat'):
                pass
            else:
                print(loaded_key)
                print(file)
                get_path('ma')
                encryptor.file_encrypt(loaded_key, file, "enc_{}".format(file))
                sleep(2)
                shutil.move(os.path.join(get_path("ma"), file), os.path.join(get_path("backup folder"), file))
        sleep(2)
        Move_files(get_path("ma"),get_path("encrption folder"),"enc_")
        

    if choice == 2:
        files = Files(get_path("encrption folder"))
        print(files)
        print("\nencrypting files.....!\n")
        for file in files:
            if file.endswith(".key") or file.endswith(".py") or file.startswith('encrypted') or file.startswith('decrypted') or file.endswith('.json') or file.startswith('archive') or file.startswith('backup') or file.startswith('bachuparchive') or file.endswith('.bat'):
                pass
            else:
                print(loaded_key)
                print(file)
                encryptor.file_decrypt(loaded_key, "{}".format(file), "dec_{}".format(file))
        sleep(2)
        Move_files(get_path("encrption folder"),get_path("decryption folder"),"dec_")

    controller()


    


if __name__ == "__main__":
    main()