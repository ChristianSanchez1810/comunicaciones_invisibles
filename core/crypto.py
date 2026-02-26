import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class AESCipher:
    def __init__(self,password):
        self.key=hashlib.sha256(password.encode('utf-8')).digest()

    def encrypt(self,raw_data):
        iv=get_random_bytes(AES.block_size)
        cipher=AES.new(self.key,AES.MODE_CBC,iv)
        encrypted_data=cipher.encrypt(pad(raw_data.encode('utf-8'),AES.block_size))
        return base64.b64encode(iv+encrypted_data).decode('utf-8')
    
    def decrypt(self,enc_data):
        try:
            enc_data=base64.b64decode(enc_data)
            iv=enc_data[:AES.block_size]
            cipher=AES.new(self.key,AES.MODE_CBC,iv)
            decrypted_data=unpad(cipher.decrypt(enc_data[AES.block_size:]),AES.block_size)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            return "ERROR: CONTRASEÑA INCORRECTA O DATOS CORRUPTOS"
        

