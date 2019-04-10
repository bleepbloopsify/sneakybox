import os
from base64 import b64encode

from Crypto.PublicKey import RSA
import requests

RSA_KEYLENGTH = 2048
KEYDIR = 'keys/'

SERVER_URI = 'http://0.0.0.0:9000'

try:
  with open(KEYDIR + 'privkey.pem', 'rb') as f:
    print("Reading private key from file: " + KEYDIR + 'privkey.pem')
    privkey = RSA.importKey(f.read())
except FileNotFoundError:
  print("Could not find private key. Generating one now")
  privkey = RSA.generate(RSA_KEYLENGTH)
  filename = KEYDIR + 'privkey.pem'
  os.makedirs(os.path.dirname(filename), exist_ok=True)
  with open(filename, 'wb') as f:
    f.write(privkey.exportKey('PEM'))

pubkey = b64encode(privkey.publickey().exportKey('DER')).decode('ascii')

print("Hello from client")

def register():
  data = {
    'pubkey': pubkey,
  }

  res = requests.post(SERVER_URI + '/register', json=data)
  if res.status_code == 400:
    return (None, None)
  res = res.json()
  if res['success']:
    return res['token'], res['uid']
  else:
    return (None, None)

def get_token(uid):
  data = {
    'pubkey': pubkey,
    'uid': uid,
  }

  res = requests.post(SERVER_URI + '/token', json=data)
  if res.status_code == 403:
    return register()

  res = res.json()
  if res['success']:
    return res['token'], uid
  else:
    return False, False


try:
  with open(KEYDIR + 'uid', 'r') as f:
    uid = f.read()
  token, uid = get_token(uid)
  with open(KEYDIR + 'uid', 'w') as f:
    f.write(uid)
except FileNotFoundError:
  token, uid = register()

  with open(KEYDIR + 'uid', 'w') as f:
    f.write(uid)

def file_upload(filepath):
  headers = {
    'Authorization': 'Bearer ' + token,
  }

  files = {
    'file': open(filepath, 'rb')
  }

  res = requests.post(SERVER_URI + '/upload', headers=headers, files=files)
  return res.text



file_upload('test.txt')
