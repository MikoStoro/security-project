
import base64
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import magic
import xml.etree.ElementTree as ET
from datetime import datetime
import os
import tkinter as tk


def generate_fake_message():
    return ''.join([ 'b' for i in range(4096)])

def generate_key_pair(length = 4096):
    length = 4096
    key = RSA.generate(length)
    private = key.exportKey('PEM')
    public = key.publickey().exportKey('PEM')
    return private,public

def save_key(key,name = "key"):
    with open(name, 'rb') as f:
        f.write(key)

mode = AES.MODE_ECB

def pin_to_hash(pin):
    return SHA256.new(pin).hexdigest()[:16].encode()

def encrypt_key_aes(data, pin):
    pin_hash = pin_to_hash(pin)
    cipher = AES.new(pin_hash, mode)
    ciphertext = cipher.encrypt(pad(data,16))
    return ciphertext

def decrypt_key_aes(data,pin):
    pin_hash = pin_to_hash(pin)
    cipher = AES.new(pin_hash, mode)
    decyphered = unpad(cipher.decrypt(data),16)
    return decyphered

def encrypt_hash(file_hash, private_key):
    private1 = RSA.import_key(private_key)
    private_signer = pkcs1_15.new(private1)

def create_signature(file_hash, private_key):
    private1 = RSA.import_key(private_key)
    SHA256.new()
    private_signer = pkcs1_15.new(private1)
    signature = private_signer.sign(file_hash)
    #return signature
    return base64.b64encode(signature).decode()


#signed_hash - string representing signed hash
#file_hash - SHA256 object
#public_key - str representing key in pem/der format
def verify_signature(file_hash: SHA256.SHA256Hash, signed_hash:str, public_key:str):
    signed_hash = base64.b64decode(signed_hash.encode())
    public1 = RSA.import_key(public)
    public_verifier = pkcs1_15.new(public1)
    try:
        public_verifier.verify(file_hash, signed_hash)
        return True
    except: 
        return False
def check_keys (msg_hash, private, public):
    private1 = RSA.import_key(private)
    public1 = RSA.import_key(public)
    private_signer = pkcs1_15.new(private1)
    public_verifier = pkcs1_15.new(public1)
    signature = private_signer.sign(msg_hash)
    try:
        public_verifier.verify(msg_hash,signature)
        return True
    except: 
        return False

def get_filetype(path):
    mime = magic.Magic(mime=True)
    return mime.from_file("testfile")

def get_file_hash(path):
    with open(path, 'rb', buffering=0) as f:
        return SHA256.new(f.read()).hexdigest()

def get_msg_hash(data):
    hash_object = SHA256.new(data)
    return hash_object

def get_file_hash(path):
    data = open(path, 'rb').read()
    hash_object = SHA256.new(data)
    return hash_object

def generate_signature(name, path_to_file, private_key):
    filename = ''.join(path_to_file.split('/')[-1].split('.')[:-1])
    filesize = str(os.path.getsize(path_to_file))
    print(filesize)
    filemod = os.path.getmtime(path_to_file)
    filemod = datetime.utcfromtimestamp(filemod)
    filemod =  filemod.strftime("%m/%d/%Y, %H:%M:%S")
    filetype = get_filetype(path_to_file)

    signature = ET.Element('signature')
    tree = ET.ElementTree(signature)
    signed_by = ET.SubElement(signature,'signed_by')
    signed_by.text = name
    sign_time = ET.SubElement(signature, "timestamp")
    sign_time.text = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

    filehash = get_file_hash(path_to_file)
    signed_filehash = create_signature(filehash,private_key)
    document_hash = ET.SubElement(signature, "document_hash")

    document_hash.text = signed_filehash
    document_metadata = ET.SubElement(signature, "document_metadata")

    metadata_name = ET.SubElement(document_metadata,"document_name")
    metadata_name.text = filename
    metadata_type = ET.SubElement(document_metadata, "document_type")
    metadata_type.text = filetype
    metadata_size = ET.SubElement(document_metadata, "document_size")
    metadata_size.text = filesize
    metadata_modification = ET.SubElement(document_metadata, "last_modification")
    metadata_modification.text = filemod


    write_name = filename + "_signature.xml"
    tree.write(write_name)
    return write_name



def verify_xml_signature(path_to_signature, path_to_file, public_key):
    tree = ET.parse(path_to_signature)
    root = tree.getroot()

    signed_by = root.find('signed_by').text
    timestamp = root.find('timestamp').text
    signed_hash = root.find('document_hash').text
    metadata = root.find('document_metadata')
    
    message = "Signed by " + signed_by + " on " + timestamp
    print(message)

    docname_ok = metadata.find("document_name").text == ''.join(path_to_file.split('/')[-1].split('.')[:-1])
    doctype_ok = metadata.find("document_type").text == get_filetype(path_to_file)
    docsize_ok = metadata.find("document_size").text ==  str(os.path.getsize(path_to_file))
    docmod_ok = metadata.find("last_modification").text == datetime.utcfromtimestamp(os.path.getmtime(path_to_file)).strftime("%m/%d/%Y, %H:%M:%S")
    print(docname_ok, doctype_ok, docsize_ok, docmod_ok)

    filehash = get_file_hash(path_to_file)
    verification_result = verify_signature(filehash, signed_hash, public_key)
    signature_status = None 
    if verification_result:
        signature_status = "Valid"
    else:
        signature_status = "Invalid"
    message = "Signature status: " + signature_status
    print(message)

    #print(signed_by,timestamp,signed_hash)


def convert_pin(pin):
    if type(pin) == bytes:
        return pin
    else:
        try:
            pin = str(pin)
            pin = pin.encode()
            return pin
        except:
            raise TypeError("pin type is invalid")

'''
HOWTO

generate_key_pair() ->bytes,bytes - generuje oba klucze 
encrypt_key_aes(klucz, pin) -> bytes - szyfruje klucz pinem
decrypt_key_aes(klucz, pin) -> bytes - odszyfrowuje klucz pinem
generate_signature(name, path, privete_key) -> str - zapisuje plik xml i zwraca nazwe

'''

'''
pin = b'1234123412341234'
message = get_msg_hash( "ABCDEF".encode())

private,public  = generate_key_pair()
save_key(private, 'private.key')
save_key(public, 'public.key')

encrypted = encrypt_key_aes(private, pin)
decrypted_key = decrypt_key_aes(encrypted, pin)

print("KEYS: " + str(check_keys(message, decrypted_key, public)))


name = "MikoStoro"
path_to_file = "fake_file.cpp"
signature_filename = generate_signature(name,path_to_file, private)
print(signature_filename)
#print(get_file_hash("fake_file.cpp") == get_file_hash("fake_folder/fake_file.cpp"))
#print(verify_signature(get_file_hash(path_to_file), signed_hash, public))
verify_xml_signature(signature_filename, path_to_file, public)
'''




def show_popup():
    popup = tk.Tk()
    popup.title('aaaa')
    popup.mainloop()



window = tk.Tk()
window.title()

window_width = 300
window_height = 200
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
center_x = int(screen_width/2 - window_width / 2)
center_y = int(screen_height/2 - window_height / 2)

window.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')



button1 = ttk.Button(window, text="popup", command=show_popup)
button1.pack()


message = tk.Label(window, text="Hello, World!")
message.pack()
window.mainloop()
#print(encrypted)
#print(decrypted_key)