import os
import time
import struct
from uuid import uuid4
from random import randint

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

AES_KEY_BITLEN = 256
AES_IVLEN = 16
AES_CHUNKSIZE = 64 * 1024

assert AES_IVLEN < AES_CHUNKSIZE, "AES IV length must be smaller than file chunksize"


RSA_KEYLEN = 4096

STORAGE_KEY_FNAME = 'storage_key'
PRIV_KEY_FNAME = 'id_rsa'


class ServerKey(object):

  def __init__(self, keydir=None):
    if keydir is None:
      self.__storage_key = get_random_bytes(AES_KEY_BITLEN // 8)
      self.__priv_key = RSA.generate(RSA_KEYLEN)
      return

    print("Getting storage key")

    storage_key_fname = keydir + '/' + STORAGE_KEY_FNAME

    try:
      with open(storage_key_fname, 'rb') as f:
        print("Reading storage key from file: " + storage_key_fname)
        self.__storage_key = f.read()
        assert len(self.__storage_key) == AES_KEY_BITLEN // 8
    except FileNotFoundError:
      print("writing new key to " + storage_key_fname)
      self.__storage_key = get_random_bytes(AES_KEY_BITLEN // 8)
      os.makedirs(os.path.dirname(storage_key_fname), exist_ok=True)
      with open(storage_key_fname, 'wb+') as f:
        f.write(self.__storage_key)
    

    print("Getting server private key")

    priv_key_fname = keydir + '/' + PRIV_KEY_FNAME

    try:
      with open(priv_key_fname, 'rb') as f:
        print("Reading privkey from file: " + priv_key_fname)
        self.__priv_key = RSA.importKey(f.read())
    except FileNotFoundError:
      print("Could not find private key. Generating one now")
      self.__priv_key = RSA.generate(RSA_KEYLEN)
      os.makedirs(os.path.dirname(priv_key_fname), exist_ok=True)
      with open(priv_key_fname, 'wb+') as f:
        f.write(self.__priv_key.exportKey())

    print("Keys setup")
  
  def encrypt_file(self, file):
    iv = get_random_bytes(AES_IVLEN)
    encryptor = AES.new(self.__storage_key, AES.MODE_CBC, iv)

    with open(file, 'rb') as reading:
      with open(file + '.enc', 'wb+') as writing:
        writing.seek(0, 0)

        filesize = os.path.getsize(file)

        chunk = reading.read(AES_CHUNKSIZE)

        writing.write(struct.pack('<Q', filesize)) # always write size
        writing.write(iv)

        while True:
          if len(chunk) == 0:
            break
          elif len(chunk) % 16 != 0:
            chunk += b' ' * (16 - (len(chunk) % 16))

          encrypted = encryptor.encrypt(chunk)
          chunk = reading.read(AES_CHUNKSIZE)
          writing.write(encrypted)
  
  def decrypt_file(self, file):
    with open(file + '.enc', 'rb') as reading:
      with open(file, 'rb+') as writing:
        writing.seek(0, 0)

        filesize = struct.unpack('<Q', reading.read(struct.calcsize('Q')))[0]
        iv = reading.read(AES_IVLEN)

        decryptor = AES.new(self.__storage_key, AES.MODE_CBC, iv)

        chunk = reading.read(AES_CHUNKSIZE)

        while True:
          if len(chunk) == 0:
            break

          decrypted = decryptor.decrypt(chunk)
          chunk = reading.read(AES_CHUNKSIZE)
          writing.write(decrypted)

        writing.truncate(filesize)

  def wrap_file(self, key):
    pass

  def unwrap_file(self, key):
    pass

PUBLIC_EXPONENT = 65537 # nye he he
KEY_EXCHANGE_MODULUS_BITLEN = 256
class KeyExchange(object):

  def __init__(self, client_exp, modulo):
    self.__id = str(uuid4())
    self.__client_exp = client_exp
    self.__public_modulo = modulo
    self.__priv_key = randint(0, 65535)
  
  def getUid(self):
    return self.__id

  def showPublicExponent(self):

    return pow(PUBLIC_EXPONENT, self.__priv_key, self.__public_modulo)
  
  def getKey(self):
    
    return pow(self.__client_exp, self.__priv_key, self.__public_modulo).to_bytes(KEY_EXCHANGE_MODULUS_BITLEN // 8, byteorder='little')



if __name__ == '__main__':
  
  target = 'target.txt'

  key = ServerKey(keydir='./keys')

  key.encrypt_file(target)

  time.sleep(5)

  key.decrypt_file(target)