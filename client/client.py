from json import load, dump, dumps
import os, sys
from base64 import b64encode

import requests
from Crypto.Cipher import AES

from crypto_utils import ClientKey, KeyExchange

SERVER_URI = 'http://0.0.0.0:9000'

class Client(object):

  def __init__(self):

    self.__key = ClientKey()
  
    try:
      with open('state.json', 'r') as f:
        self.__state = load(f)
    except FileNotFoundError:
      self.__state = {
        'uuid': None,
        'files': {},
      }
    
    if 'uuid' not in self.__state or 'files' not in self.__state:
      self.__state = {
        'uuid': None,
        'files': {},
      }

    self.__kex = KeyExchange()

  def get_uuid(self):
    key = self.__key
    state = self.__state

    data = {
      'pubkey': key.publicKey(),
    }

    res = requests.post(SERVER_URI + '/register', json=data)

    if res.status_code != 200:
      print('[upload] Failed to retrive nonce and token from server? Is the server running?')
      exit(1)
    
    body = res.json()
    if not body['success']:
      print('[upload] Server side error')
      print(body)
      exit(1)

    state['uuid'] = body['uuid']

    self.__nonce = body['nonce']
    self.__state = state
  
  def save(self):
    with open('state.json', 'w+') as f:
      dump(self.__state, f)

  def get_nonce(self):
    key = self.__key
    state = self.__state

    data = {
      'pubkey': key.publicKey(),
      'uuid': state['uuid'],
    }

    res = requests.post(SERVER_URI + '/nonce', json=data)

    if res.status_code != 200:
      print('[upload] Failed to retrive nonce from server? Is the server running')
      
      return self.get_uuid() # we are assuming the uuid broke

    body = res.json()
    if not body['success']:
      print('[upload] Server side error')
      print(body)
      return
      
    self.__nonce = body['nonce']

  def init_kex(self):
    key = self.__key
    state = self.__state

    exp, mod = self.__kex.showPublicModulus()

    data = {
      'uuid': state['uuid'],
      'nonce': key.sign(self.__nonce + 1)[0],
    }

    self.__nonce += 1

    headers = {
      'X-Data': b64encode(dumps(data).encode('utf-8')),
    }

    body = {
      'client_exp': b64encode(hex(exp).encode('utf-8')),
      'pub_mod': b64encode(hex(mod).encode('utf-8')),
    }

    self.__state = state

    res = requests.post(SERVER_URI + '/kexinit', headers=headers, data=body)
    if res.status_code != 200:
      print(res.text)
      return
    
    res = res.json()

    self.__kex.setServerPubMod(res['pub_exp'], res['uid'])

  def upload(self, fname):

    key = self.__key
    state = self.__state

    data = {
      'uuid': state['uuid'],
      'nonce': key.sign(self.__nonce + 1)[0],
      'kexid': self.__kex.getUid(),
    }

    self.__nonce += 1

    headers = {
      'X-Data': b64encode(dumps(data).encode('utf-8')),
    }

    aeskey = self.__kex.getKey()
    print(aeskey)

    cipher = AES.new(key=aeskey, mode=AES.MODE_ECB)

    data = open(fname, 'r').read()
    data += '\x00' * (16 - len(data) % 16)

    files = {
      'file': cipher.encrypt(data),
    }

    res = requests.post(SERVER_URI + '/upload', headers=headers, files=files)

    if res.status_code != 200:
      print(res.text)
      print("There was an error", file=sys.stderr)

    fileid = res.json()['fileid']

    state['files'][fname] = fileid

    self.__state = state

    return fileid

  def download(self, fileid):

    key = self.__key
    state = self.__state

    data = {
      'uuid': state['uuid'],
      'nonce': key.sign(self.__nonce + 1)[0],
      'kexid': self.__kex.getUid(),
    }

    headers = {
      'X-Data': b64encode(dumps(data).encode('utf-8')),
    }

    self.__nonce += 1

    res = requests.get(SERVER_URI + '/download/' + fileid, headers=headers, allow_redirects=True)

    if res.status_code != 200:
      print('[download] Failed to retrive file.')
      exit(1)

    fpath = os.path.join('downloads', fileid)
    os.makedirs(os.path.dirname(fpath), exist_ok=True)

    with open('downloads/' + fileid, 'wb') as file:
      file.write(bytes(res.content))
      print('[download] File downloaded! Check your downloads folder for the file.')
    
    self.__state = state