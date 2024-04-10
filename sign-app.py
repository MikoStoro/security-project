from random import randbytes
from Crypto.Cipher import AES
from OpenSSL import crypto 
import signxml

def generate_fake_key():
    return ''.join([ 'b' for i in range(4096)])

def generate_rsa_key():
    length = 4096
    key = randbytes(length)
    return key

def generate_key_pair(length = 4096):
    pk = crypto.PKey()
    pk.generate_key(crypto.TYPE_RSA, 4096)
    private = ''.join(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk).decode().split('\n')[1:-2]).encode()
    public = ''.join(crypto.dump_publickey(crypto.FILETYPE_PEM, pk).decode().split('\n')[1:-2]).encode()
    return private, public



mode = AES.MODE_ECB

def encrypt_information_aes(data, pin):
    cipher = AES.new(pin, mode)
    ciphertext = cipher.encrypt(data)
    return ciphertext

def decrypt_information_aes(data,pin):
    cipher = AES.new(pin, mode)
    decyphered = cipher.decrypt(data)

    print("Message:", decyphered.decode('unicode_escape'))

def encrypt_data_rsa(data, key):
    pass


private,public  = generate_key_pair()
#print(private)
encrypted = encrypt_information_aes(private, b'1234123412341234')
#decrypt_information_aes(encrypted, b'3456345634563456')
decrypt_information_aes(encrypted, b'1234123412341234')