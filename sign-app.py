
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import hashlib
from Crypto.Util.Padding import pad, unpad
import magic
import xml.etree.ElementTree as ET
from datetime import datetime
import os

def generate_fake_message():
    return ''.join([ 'b' for i in range(4096)])

def generate_key_pair(length = 4096):
    length = 4096
    key = RSA.generate(length)
    private = key.exportKey('PEM')
    public = key.publickey().exportKey('PEM')
    return private,public


mode = AES.MODE_ECB

def pin_to_hash(pin):
    return hashlib.sha256(pin).hexdigest()[:16].encode()

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

def decrypt_hash(file_hash, public_key):
    public1 =  RSA.import_key(public_key)

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
    with open(filename, 'rb', buffering=0) as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def get_msg_hash(data):
    hash_object = SHA256.new(data)
    return hash_object

def get_file_hash(path):
    data = open(path, 'rb').read()
    hash_object = SHA256.new(data)
    return hash_object



pin = b'1234123412341234'
message = get_msg_hash( "ABCDEF".encode())

private,public  = generate_key_pair()
encrypted = encrypt_key_aes(private, pin)
decrypted_key = decrypt_key_aes(encrypted, pin)

print("KEYS: " + str(check_keys(message, private, public)))

fake_hash = "1234567890"
#signer = xades.XAdESSigner()
#root = signer.sign(fake_hash, key=private)
#print(root)
def generate_xml(name, path_to_file, private_key):
    #name = "MikoStoro"
    #path_to_file = "fake_file.cpp"
    filename = path_to_file.split('/')[-1]
    filesize = str(os.path.getsize(path_to_file))
    print(filesize)
    filemod = os.path.getmtime(path_to_file)
    filemod = datetime.utcfromtimestamp(filemod)
    filemod =  filemod.strftime("%m/%d/%Y, %H:%M:%S")
    filetype = get_filetype(path_to_file)

    signature = ET.Element('signature')
    signed_by = ET.SubElement(signature,'signed_by')
    signed_by.text = name
    sign_time = ET.SubElement(signature, "timestamp")
    sign_time.text = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")


    document_hash = ET.SubElement(signature, "document_hash")
    filehash = get_file_hash(path_to_file).hexdigest()
    encrypted_hash = en
    document_hash.text = get_file_hash(path_to_file)


    document_metadata = ET.SubElement(signature, "document_metadata")
    metadata_name = ET.SubElement(document_metadata,"document_name")
    metadata_name.text = filename
    metadata_type = ET.SubElement(document_metadata, "document_type")
    metadata_type.text = filetype
    metadata_size = ET.SubElement(document_metadata, "document_size")
    metadata_size.text = filesize
    metadata_modification = ET.SubElement(document_metadata, "last_modification")
    metadata_modification.text = filemod

    ET.dump(signature)
    return signature


name = "MikoStoro"
path_to_file = "fake_file.cpp"
filename = path_to_file.split('/')[-1]
filesize = str(os.path.getsize(path_to_file))
print(filesize)
filemod = os.path.getmtime(path_to_file)
filemod = datetime.utcfromtimestamp(filemod)
filemod =  filemod.strftime("%m/%d/%Y, %H:%M:%S")
filetype = get_filetype(path_to_file)

signature = ET.Element('signature')
signed_by = ET.SubElement(signature,'signed_by')
signed_by.text = name
sign_time = ET.SubElement(signature, "timestamp")
sign_time.text = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

filehash = get_file_hash(path_to_file).hexdigest()
document_hash = ET.SubElement(signature, "document_hash")
document_hash.text = filehash
document_metadata = ET.SubElement(signature, "document_metadata")

metadata_name = ET.SubElement(document_metadata,"document_name")
metadata_name.text = filename
metadata_type = ET.SubElement(document_metadata, "document_type")
metadata_type.text = filetype
metadata_size = ET.SubElement(document_metadata, "document_size")
metadata_size.text = filesize
metadata_modification = ET.SubElement(document_metadata, "last_modification")
metadata_modification.text = filemod



ET.dump(signature)
#print(get_file_hash("fake_file.cpp") == get_file_hash("fake_folder/fake_file.cpp"))

#print(encrypted)
#print(decrypted_key)