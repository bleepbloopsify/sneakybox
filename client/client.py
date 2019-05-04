from json import load, dump
import os

import requests

from crypto_utils import ClientKey

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
        'files': [],
      }
    
    if 'uuid' not in self.__state or 'files' not in self.__state:
      self.__state = {
        'uuid': None,
        'files': [],
      }

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

  def upload(self, fname):

    key = self.__key
    state = self.__state

    data = {
      'uuid': state['uuid'],
      'nonce': key.sign(self.__nonce),
    }

    files = {
      'file': open(fname, 'r').read(),
    }

    res = requests.post(SERVER_URI + '/upload', json=data, files=files)
    print(res.text)

  def download(self, fileid):

    key = self.__key
    state = self.__state

    data = {
      'uuid': state['uuid'],
      'nonce': key.sign(self.__nonce),
    }

    res = requests.get(SERVER_URI + '/download/' + fileid, allow_redirects=True)

    if res.status_code != 200:
      print('[download] Failed to retrive file.')
      exit(1)

    fpath = os.path.join('downloads', fileid)
    os.makedirs(os.path.dirname(fpath), exist_ok=True)

    with open('downloads/' + fileid, 'wb') as file:
      file.write(bytes(res.content))
      print('[download] File downloaded! Check your downloads folder for the file.')
