import os
from base64 import b64encode
import struct
from random import randint, getrandbits


from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

PRIV_KEY_FNAME = 'id_rsa'
RSA_KEYLEN = 2048

class ClientKey(object):

  def __init__(self, keydir='./keys'):

    # print("[crypto_utils] Getting client public key")

    key_fname = os.path.join(keydir, PRIV_KEY_FNAME)
    try:
      with open(key_fname, 'rb') as f:
        # print('[crypto_utils] Reading privkey from file: ' + key_fname)
        self.__priv_key = RSA.importKey(f.read())
    except FileNotFoundError:
      self.__priv_key = RSA.generate(RSA_KEYLEN)
      os.makedirs(os.path.dirname(key_fname), exist_ok=True)
      with open(key_fname, 'wb+') as f:
        f.write(self.__priv_key.exportKey())
      
  def publicKey(self):
    '''
    returns base64 encoded DER (binary) format
    public key (for sending to server)
    '''
    public = self.__priv_key.publickey()
    return b64encode(public.exportKey(format='DER')).decode('utf-8')


  def sign(self, data):
    return self.__priv_key.sign(data, 'yeet')



PUBLIC_EXPONENT = 65537 # nye he he
KEY_EXCHANGE_MODULUS_BITLEN = 256
class KeyExchange(object):

  def __init__(self):

    self.__priv_key = randint(0, 65535) # should maybe make this larger
    self.__public_modulo = getrandbits(KEY_EXCHANGE_MODULUS_BITLEN)

  def showPublicModulus(self):

    return pow(PUBLIC_EXPONENT, self.__priv_key, self.__public_modulo), self.__public_modulo
  
  def setServerPubMod(self, server_pub_mod, uid):
    self.__uuid = uid
    self.__server_pub_mod = server_pub_mod

  def getUid(self):
    return self.__uuid

  def getKey(self):
    return pow(self.__server_pub_mod, self.__priv_key,self.__public_modulo).to_bytes(KEY_EXCHANGE_MODULUS_BITLEN // 8, byteorder='little')

if __name__ == '__main__':
  kex = KeyExchange()
  print(kex.showPublicModulus())