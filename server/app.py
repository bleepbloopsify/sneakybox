import os
import struct
from uuid import uuid4
from base64 import b64decode, b64encode
from datetime import datetime
from json import dumps
from functools import wraps
from tempfile import NamedTemporaryFile

from flask import Flask, jsonify, request, abort, send_file, g
from werkzeug.utils import secure_filename
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

from crypto_utils import ServerKey

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

@app.route("/", methods=['GET'])
def index():

  return "Hello World!"

# TODO: POST /register

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
    'files': [],
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

'''
POST /upload
checks identity
generates a fileid
'''
@app.route('/upload', methods=['POST'])
def upload():
  if 'file' not in request.files:
    return abort(400)
  file = request.files['file']
  # if user does not select file, browser also
  # submit an empty part without filename

  body = request.get_json()
  print(body)

  if file.filename == '':
    return abort(400)
  if file:
    fileid = str(uuid4())
    fpath = os.path.join('files', fileid)

    os.makedirs(os.path.dirname(fpath), exist_ok=True)

    file.save(fpath)

    return jsonify({
      'success': True,
      'fileid': fileid,
    })

  # TODO: generate random filename

# TODO: GET /download
'''
GET /download
request using the token provided above
'''
@app.route('/download/<string:id>', methods=['GET'])
def download(id):
  
  # TODO: get fname by id
  fname = None

  return send_file(fname)



if __name__ == '__main__':

  print("Hello")

  app.run('0.0.0.0', port=9000, debug=True)