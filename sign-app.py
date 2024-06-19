
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
from tkinter import filedialog as fd

def generate_fake_message():
    return ''.join([ 'b' for i in range(4096)])

def generate_key_pair(length = 4096):
    length = 4096
    key = RSA.generate(length)
    private = key.exportKey('PEM')
    public = key.publickey().exportKey('PEM')
    return private,public

def save_key(key,name = "key"):
    with open(name, 'wb') as f:
        f.write(key)

mode = AES.MODE_CBC
iv = b'1234123412341234'

def pin_to_hash(pin):
    return SHA256.new(pin).hexdigest()[:16].encode()

def encrypt_key_aes(data, pin):
    pin_hash = pin_to_hash(pin)
    cipher = AES.new(pin_hash, mode,iv)
    ciphertext = cipher.encrypt(pad(data,16))
    return ciphertext

def decrypt_key_aes(data,pin):
    pin_hash = pin_to_hash(pin)
    cipher = AES.new(pin_hash, mode, iv)
    decyphered = unpad(cipher.decrypt(data),16)
    return decyphered

def create_signature(file_hash, private_key):
    try:
        private1 = RSA.import_key(private_key)
    except:
        tk.messagebox.showerror('error', 'Pin is incorrect or an invalid key was chosen')
        return
    private_signer = pkcs1_15.new(private1)
    signature = private_signer.sign(file_hash)
    #return signature
    return base64.b64encode(signature).decode()


#signed_hash - string representing signed hash
#file_hash - SHA256 object
#public_key - str representing key in pem/der format
def verify_signature(file_hash: SHA256.SHA256Hash, signed_hash:str, public_key:str):
    signed_hash = base64.b64decode(signed_hash.encode())
    public1 = RSA.import_key(public_key)
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
    return magic.from_file(path, mime = True)

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

def generate_signature_xml(name, path_to_file, private_key_path, pkey_pin:str):
    filename = ''.join(path_to_file.split('/')[-1].split('.')[:-1])
    filesize = str(os.path.getsize(path_to_file))
    filemod = os.path.getmtime(path_to_file)
    filemod = datetime.utcfromtimestamp(filemod)
    filemod =  filemod.strftime("%m/%d/%Y, %H:%M:%S")
    filetype = get_filetype(path_to_file)


    private_key=get_private_key(private_key_path, pkey_pin.encode())
    print("PKEY: " + str(private_key))
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
    tk.messagebox.showinfo('information', 'Signature created as: ' + str(write_name))
    return write_name



def verify_xml_signature(path_to_signature, path_to_file, public_key):
    tree = ET.parse(path_to_signature)
    root = tree.getroot()

    signed_by = root.find('signed_by').text
    timestamp = root.find('timestamp').text
    signed_hash = root.find('document_hash').text
    metadata = root.find('document_metadata')
    
    message = "Signed by " + signed_by + " on " + timestamp + "\n\n"
    print(message)

    docname_ok = metadata.find("document_name").text == ''.join(path_to_file.split('/')[-1].split('.')[:-1])
    doctype_ok = metadata.find("document_type").text == get_filetype(path_to_file)
    docsize_ok = metadata.find("document_size").text ==  str(os.path.getsize(path_to_file))
    docmod_ok = metadata.find("last_modification").text == datetime.utcfromtimestamp(os.path.getmtime(path_to_file)).strftime("%m/%d/%Y, %H:%M:%S")
    print(docname_ok, doctype_ok, docsize_ok, docmod_ok)
    
    metadata_ok = (docname_ok and docsize_ok and doctype_ok and docmod_ok)
    print(metadata_ok)
    if docname_ok: docname_ok = 'Unchanged'
    else: docname_ok = 'Changed'

    if doctype_ok: doctype_ok = 'Unchanged'
    else: doctype_ok = 'Changed'
    
    if docsize_ok: docsize_ok = 'Unchanged'
    else: docsize_ok = 'Changed'

    if docmod_ok: docmod_ok = 'Unchanged'
    else: docmod_ok = 'Changed'

    filehash = get_file_hash(path_to_file)
    verification_result = verify_signature(filehash, signed_hash, public_key)
    signature_status = None 
    if verification_result:
        signature_status = "Valid"
    else:
        signature_status = "Invalid"
    message += "SIGNATURE STATUS: " + signature_status +"\n"


    message += "Document name: " + str(docname_ok) + "\n"
    message += "Document type: " + str(doctype_ok) + "\n"
    message += "Document size: " + str(docsize_ok) + "\n"
    message += "Last modification time: " + str(docmod_ok) + "\n"

    if signature_status == "Valid":
        if metadata_ok:
            tk.messagebox.showinfo('information', message)
        else:
            tk.messagebox.showwarning('warning', message)
    else:
        tk.messagebox.showerror('error', message)


    print(message)

    #print(signed_by,timestamp,signed_hash)

def get_private_key(path,pin):
    file = open(path, 'rb')
    key = file.read()
    file.close()
    return decrypt_key_aes(key, pin)

def get_public_key(path):
    file = open(path, 'rb')
    key = file.read()
    file.close()
    return key

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


class keys_win():
    def __init__():
        pass

class GUIAPP:

    def alert(self, message):
        alert = tk.Tk()
        alert.geometry(f'{self.window_width}x{self.window_height}+{self.center_x}+{self.center_y}')
        alert.title("Alert")
        
        label_message = ttk.Label(alert, text=message)
        btn_alert = ttk.Button(alert, text="OK", command=lambda:alert.destroy())
        
        label_message.pack()
        btn_alert.pack()

        alert.mainloop()

    def btn_generate_fun(self, key_name, pin):
        if(len(str(pin)) < 4):
            self.alert("PIN must be at least 4 characters long!")
            return False
        
        pin = convert_pin(pin)

        private_name =  "private.key"
        public_name = "public.key"


        if key_name != '':
            private_name = key_name + '.' + private_name
            public_name = key_name + '.' + public_name

        private,public = generate_key_pair()
        encrypted_private = encrypt_key_aes(private,pin)
        save_key(public,public_name)
        save_key(encrypted_private,private_name)

        self.alert("Successfully generated keyes:\n" + public_name + "\n" + private_name)
        return True

    def keys_window(self):
        close_window = False
        self.keys_popup = tk.Tk()
        self.keys_popup.geometry(f'{self.window_width}x{self.window_height}+{self.center_x}+{self.center_y}')
        self.keys_popup.title('Keys generation')

        label_kname = ttk.Label(self.keys_popup, text="Name")
        entry_kname = ttk.Entry(self.keys_popup)
        label_pin = ttk.Label(self.keys_popup, text="PIN")
        entry_pin =  ttk.Entry(self.keys_popup)
        btn_generate = ttk.Button(self.keys_popup, text="Generate", command=lambda: self.btn_generate_fun(entry_kname.get(), entry_pin.get()))
        btn_close = ttk.Button(self.keys_popup, text="Back", command= lambda: self.keys_popup.destroy())
        
        label_kname.pack()
        entry_kname.pack()
        label_pin.pack()
        entry_pin.pack()
        btn_generate.pack()
        btn_close.pack()

        self.keys_popup.mainloop()
        
    def select_file(self, reason):
        filename = fd.askopenfilename(
            title='Please select a file',
            initialdir='.')
        
        if reason == 'doc':
            self.selected_document = filename
            self.selected_document_hash = get_file_hash(filename)
        if reason == 'key':
            self.selected_key = filename
        if reason == 'signature':
            self.selected_signature = filename

    def sign_window(self):
        self.selected_document = ''
        self.selected_key = ''
        self.sign_popup = tk.Tk()
        self.sign_popup.geometry(f'{self.window_width}x{self.window_height}+{self.center_x}+{self.center_y}')
        self.sign_popup.title('Sign document')
        

        label_selected_doc = ttk.Label(self.sign_popup, text='no document selected')
        label_selected_key = ttk.Label(self.sign_popup, text='no key selected')
        label_name = ttk.Label(self.sign_popup, text="Enter your name")
        entry_name = ttk.Entry(self.sign_popup)
        btn_select_doc = ttk.Button(self.sign_popup, text="select document", command=lambda: (self.select_file('doc'), label_selected_doc.config(text=self.selected_document),self.sign_popup.lift()))
        btn_select_key = ttk.Button(self.sign_popup, text="select private key (encrypted)", command=lambda: (self.select_file('key'), label_selected_key.config(text=self.selected_key),self.sign_popup.lift())) 
        label_pin = ttk.Label(self.sign_popup, text="Private key's pin")
        entry_pin = ttk.Entry(self.sign_popup)


        btn_sign = ttk.Button(self.sign_popup, text="Sign the document", command=lambda: generate_signature_xml(entry_name.get(),self.selected_document,self.selected_key,entry_pin.get()))

        label_name.pack()
        entry_name.pack()
        btn_select_doc.pack()
        label_selected_doc.pack()
        btn_select_key.pack()
        label_selected_key.pack()
        label_pin.pack()
        entry_pin.pack()
        
        btn_sign.pack()

        self.sign_popup.mainloop()

    def verify_window(self):
        self.selected_document = ''
        self.selected_key = ''
        self.selected_signature = ''
        self.verify_popup = tk.Tk()
        self.verify_popup.geometry(f'{self.window_width}x{self.window_height}+{self.center_x}+{self.center_y}')
        self.verify_popup.title('Verify signature')
        

        label_selected_doc = ttk.Label(self.verify_popup, text='no document selected')
        label_selected_key = ttk.Label(self.verify_popup, text='no key selected')
        label_selected_sig = ttk.Label(self.verify_popup, text='no signature selected')
        btn_select_sig = ttk.Button(self.verify_popup, text="select signature", command=lambda: (self.select_file('signature'), label_selected_sig.config(text=self.selected_signature),self.verify_popup.lift()))

        btn_select_doc = ttk.Button(self.verify_popup, text="select document", command=lambda: (self.select_file('doc'), label_selected_doc.config(text=self.selected_document),self.verify_popup.lift()))
        
        btn_select_key = ttk.Button(self.verify_popup, text="select public key", command=lambda: (self.select_file('key'), label_selected_key.config(text=self.selected_key),self.verify_popup.lift())) 

        btn_verify = ttk.Button(self.verify_popup, text="Verify signature", command=lambda: verify_xml_signature(self.selected_signature,self.selected_document,get_public_key(self.selected_key)))


        btn_select_sig.pack()
        label_selected_sig.pack()
        btn_select_doc.pack()
        label_selected_doc.pack()
        btn_select_key.pack()
        label_selected_key.pack()

        
        btn_verify.pack()

        self.verify_popup.mainloop()

    def __init__(self):
        self.window = tk.Tk()
        self.window.title()
        self.window_width = 300
        self.window_height = 200
        self.screen_width = self.window.winfo_screenwidth()
        self.screen_height = self.window.winfo_screenheight()
        self.center_x = int(self.screen_width/2 - self.window_width / 2)
        self.center_y = int(self.screen_height/2 - self.window_height / 2)

        popup1 = None
        popup2 = None
        self.window.geometry(f'{self.window_width}x{self.window_height}+{self.center_x}+{self.center_y}')
        self.window.title("EPIC SECURITY APP")


        btn_generate_key = ttk.Button(self.window, text="Generate key pair", command=self.keys_window)
        btn_sign_doc = ttk.Button(self.window, text="Sign document", command=self.sign_window)
        btn_verify_doc = ttk.Button(self.window, text="Verify signature", command=self.verify_window)

        btn_generate_key.pack()
        btn_sign_doc.pack()
        btn_verify_doc.pack()
        self.window.mainloop()

app = GUIAPP()

generate_signature_xml('miko', "./fake_file.cpp", private_key=get_private_key("key.private.key", b'1234'))
verify_xml_signature("./fake_file_signature.xml", './fake_file.cpp', get_public_key('./key.public.key'))

#print(encrypted)
#print(decrypted_key)