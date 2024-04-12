from random import randbytes
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import Crypto.IO.PEM as PEM
from OpenSSL import crypto
import hashlib
import signxml.xades as xades
import base64
from Crypto.Util.Padding import pad, unpad
import magic
import xml.etree.ElementTree as ET
import datetime

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

def check_keys (data, private, public):
    private1 = RSA.import_key(private)
    public1 = RSA.import_key(public)
    public_encoder = PKCS1_OAEP.new(public1)
    private_decoder = PKCS1_OAEP.new(private1)
    encrypted = public_encoder.encrypt(data)
    decrpyted = private_decoder.decrypt(encrypted)
    if data == decrpyted:
        return True
    return False

def get_filetype(path):
    mime = magic.Magic(mime=True)
    return mime.from_file("testfile")



pin = b'1234123412341234'
message = "ABCDEF".encode()

'''private,public  = generate_key_pair()
encrypted = encrypt_key_aes(private, pin)
decrypted_key = decrypt_key_aes(encrypted, pin)

print(check_keys(message, private, public))
'''
fake_hash = "1234567890"
#signer = xades.XAdESSigner()
#root = signer.sign(fake_hash, key=private)
#print(root)

name = "MikoStoro"

signature = ET.Element('signature')
signed_by = ET.SubElement(signature,'signed_by')
signed_by_content = ET.tes
sign_time = ET.SubElement(signature,str(datetime.datetime))


ET.dump(signature)


#print(encrypted)
#print(decrypted_key)