from random import randbytes
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import Crypto.IO.PEM as PEM
from OpenSSL import crypto
import hashlib
import signxml
import base64
from Crypto.Util.Padding import pad, unpad

def generate_fake_message():
    return ''.join([ 'b' for i in range(4096)])

def generate_key_pair(length = 4096):
    length = 4096
    key = RSA.generate(length)
    #(key.publickey().exportKey())
    #print(key.exportKey())
    #pk = crypto.PKey()
    #pk.generate_key(crypto.TYPE_RSA, length)
    #pk.to_cryptography_key()
    #print("LENGHTH " + str(len(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk).decode('unicode_escape'))))
    private = key.exportKey('DER')
    public = key.publickey().exportKey('DER')


    print(public)
    '''private_trimmed = ''.join(list(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk).decode('unicode_escape'))[28:-27]).encode()
    public_trimmed = ''.join(list(crypto.dump_publickey(crypto.FILETYPE_PEM, pk).decode('unicode_escape'))[27:-26]).encode()
    private = crypto.dump_privatekey(crypto.FILETYPE_PEM, pk)
    public = crypto.dump_publickey(crypto.FILETYPE_PEM, pk)'''
    #print(private.decode(), private_trimmed.decode())
    #print(public.decode(), public_trimmed.decode())
    #return private_trimmed, public_trimmed
    return private,public
'''
def generate_key_pair(length = 4096):
    key = RSA.generate(length)
    private = key.export_key()
    public = key.public_key().export_key()
    print(private)
    return private,public
'''


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
    print("Message:", decyphered.decode('unicode_escape'))
    return decyphered

def check_keys (data, private, public):
    private1 = RSA.import_key(private)
    public1 = RSA.import_key(public)
    public_encoder = PKCS1_OAEP.new(public1)
    private_decoder = PKCS1_OAEP.new(private1)
    encrypted = public_encoder.encrypt(data)
    print(private_decoder.decrypt(encrypted))



'''
def encrypt_key_aes(data, pin):
    pin_hash = pin_to_hash(pin)

    cipher = AES.new(pin_hash, mode)
    ciphertext = cipher.encrypt(pad(data,16))
    return ciphertext

def decrypt_key_aes(data,pin):
    pin_hash = pin_to_hash(pin)
    cipher = AES.new(pin_hash, mode)
    decyphered = unpad(cipher.decrypt(data),16)
    print("Message:", decyphered.decode('unicode_escape'))
    return decyphered

'''

pin = b'1234123412341234'
message = "ABCDEF".encode()
private,public  = generate_key_pair()
encrypted = encrypt_key_aes(private, pin)
decrypted_key = decrypt_key_aes(encrypted, pin)

check_keys(message, private, public)

#print(encrypted)
#print(decrypted_key)