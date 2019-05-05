import os
import struct
from uuid import uuid4
from base64 import b64decode, b64encode
from datetime import datetime
from json import dumps, loads
from functools import wraps
from tempfile import NamedTemporaryFile
from io import BytesIO

from flask import Flask, jsonify, request, abort, send_file, g, after_this_request
from werkzeug.utils import secure_filename
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

from crypto_utils import ServerKey, KeyExchange

RSA_KEYLENGTH = 4096
KEYDIR = 'keys/'

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

app = Flask(__name__)

app.key = ServerKey(keydir='./keys')

db = {
  'pubkeys': {},
  'uuids': {},
} # we're using a dictionary in lieu of an actual database for simplicity's sake

exchanges = {}

@app.route("/", methods=['GET'])
def index():

  return "Hello World!"

@app.route('/uuid', methods=['POST'])
def getuuid():

  data = request.get_json()

  if 'pubkey' not in data:
    return abort(400, "No pubkey")
  
  b64pubkey = data['pubkey']

  pubkey = RSA.importKey(b64decode(b64pubkey))
  if b64pubkey in db['pubkeys']:
    return jsonify({
      'success': True,
      'uuid': db['pubkeys']['pubkey'],
    })

  uid = str(uuid4())
  while uid in db['uuids']:
    uid = str(uuid4())

  db['pubkeys'][b64pubkey] = uid

  db['uuids'][uid] = {
    'pubkey': pubkey,
    'files': {},
  }

  return jsonify({
    'success': True,
    'uuid': uid,
  })

'''
Register will receive the client's public key
'''
@app.route('/register', methods=['POST'])
def register():

  data = request.get_json()
  if 'pubkey' not in data:
    return abort(400, "No pubkey found in json body")
  nonce = struct.unpack('<I', Random.get_random_bytes(4))[0]

  b64pubkey = data['pubkey']

  if b64pubkey in db['pubkeys']:
    uid = db['pubkeys'][b64pubkey]
  else:
    uid = str(uuid4())
    while uid in db['uuids']:
      uid = str(uuid4())
  
  db['uuids'][uid] = {
    'pubkey': b64pubkey, # we only store strings
    'nonce': nonce,
    'files': {},
  }

  return jsonify({
    'success': True,
    'uuid': uid,
    'nonce': nonce
  })

'''
refetch nonce
'''
@app.route('/nonce', methods=['POST'])
def token():
  data = request.get_json()
  if 'pubkey' not in data or 'uuid' not in data:
    return abort(400, "No pubkey or uid found in json body")
  
  uid = data['uuid']
  if uid not in db['uuids']:
    return abort(403, 'Uid not found in database')

  state = db['uuids'][uid]
  pubkey = state['pubkey']

  if pubkey != data['pubkey']:
    return 403, jsonify({ 'success': False, 'message': 'pubkeys do not match' })

  return jsonify({
    'success': True,
    'nonce': state['nonce'],
  })

@app.route('/kexinit', methods=['POST'])
def kexinit():
  if 'X-Data' not in request.headers:
    return abort(400, "Missing X-Data header")

  payload = request.headers['X-Data']

  body =  loads(b64decode(payload))

  if 'uuid' not in body or 'nonce' not in body:
    return abort(400, 'Missing parameters')

  uuid = body['uuid']
  signednonce = body['nonce']

  state = db['uuids'].get(uuid, None)
  if state is None:
    return abort(403, "That uuid was not found")
  
  pubkey = RSA.importKey(b64decode(state['pubkey']))
  nonce = pubkey.encrypt(signednonce, 'yeet')[0]

  if nonce <= state['nonce']:
    return abort(403, "That nonce is no longer valid")

  state['nonce'] += 1 # it worked so we keep going

  body = request.values
  if 'client_exp' not in body or 'pub_mod' not in body:
    return abort(400, 'Missing paramters client_exp or pub_mod')
    
  client_exp = int(b64decode(body['client_exp']), 16)
  pub_mod = int(b64decode(body['pub_mod']), 16)

  kex = KeyExchange(client_exp, pub_mod)
  uid = kex.getUid()
  exchanges[uid] = kex

  return jsonify({
    'pub_exp': kex.showPublicExponent(),
    'uid': kex.getUid(),
  })

'''
POST /upload
checks identity
generates a fileid
'''
@app.route('/upload', methods=['POST'])
def upload():

  if 'X-Data' not in request.headers:
    return abort(400, "Missing X-Data header")

  payload = request.headers['X-Data']

  body =  loads(b64decode(payload))

  if 'uuid' not in body or 'nonce' not in body or 'kexid' not in body:
    return abort(400, 'Missing parameters')

  uuid = body['uuid']
  signednonce = body['nonce']
  kexid = body['kexid']

  state = db['uuids'].get(uuid, None)
  if state is None:
    return abort(403, "That uuid was not found")
  
  pubkey = RSA.importKey(b64decode(state['pubkey']))
  nonce = pubkey.encrypt(signednonce, 'yeet')[0]

  if nonce <= state['nonce']:
    return abort(403, "That nonce is no longer valid")

  state['nonce'] += 1 # it worked so we keep going

  db['uuids'][uuid] = state

  if kexid not in exchanges:
    return abort(400, "KexID incorrect")
  
  kex = exchanges[kexid]
  aeskey = kex.getKey()

  cipher = AES.new(aeskey, mode=AES.MODE_ECB)

  for fname, file in request.files.items():
    # if user does not select file, browser also
    # submit an empty part without filename

    if file.filename == '':
      return abort(400)
    if file:
      fileid = str(uuid4())
      fpath = os.path.join('files', fileid)

      os.makedirs(os.path.dirname(fpath), exist_ok=True)

      file.save(fpath)
      with open(fpath, 'rb') as f:
        decrypted = cipher.decrypt(f.read())
        with open(fpath, 'wb+') as w:
          w.write(decrypted)

      app.key.encrypt_file(fpath)

      state['files'][fileid] = {
        'filename': file.filename,
      }
      db['uuids'][uuid] = state

      del exchanges[kexid]

      return jsonify({
        'success': True,
        'fileid': fileid,
      })

'''
GET /download
request using the token provided above
'''
@app.route('/download/<string:id>', methods=['GET'])
def download(id):

  if 'X-Data' not in request.headers:
    return abort(400, "Missing X-Data header")

  payload = request.headers['X-Data']

  body =  loads(b64decode(payload))

  if 'uuid' not in body or 'nonce' not in body:
    return abort(400, 'Missing parameters')

  uuid = body['uuid']
  signednonce = body['nonce']
  kexid = body['kexid']

  state = db['uuids'].get(uuid, None)
  if state is None:
    return abort(403, "That uuid was not found")

  pubkey = RSA.importKey(b64decode(state['pubkey']))
  nonce = pubkey.encrypt(signednonce, 'yeet')[0]

  if nonce <= state['nonce']:
    return abort(403, "That nonce is no longer valid")

  state['nonce'] += 1 # it worked so we keep going
  db['uuids'][uuid] = state

  if kexid not in exchanges:
    return abort(400, "KexID incorrect")
  
  kex = exchanges[kexid]
  aeskey = kex.getKey()

  cipher = AES.new(aeskey, mode=AES.MODE_ECB)

  if id not in state['files']:
    return abort(404, "File not uploaded")

  fstate = state['files'][id]

  try:
    strio = BytesIO()
    app.key.decrypt_file(os.path.join('files', id))
    with open(os.path.join('files', id), 'rb') as f:
      strio.write(cipher.encrypt(f.read()))

    try:
      os.remove(os.path.join('files', id))
    except:
      print("Error deleting file?")

    strio.seek(0)
    del exchanges[kexid]

    return send_file(strio, attachment_filename=fstate['filename'], as_attachment=True)
  except FileNotFoundError as e:
    print(e)
    return abort(404)

if __name__ == '__main__':

  print("Hello")

  app.run('0.0.0.0', port=9000, debug=True)