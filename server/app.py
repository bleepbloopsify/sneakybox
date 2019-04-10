import os
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
db = {
  'uuids': {},
  'files': {}, 
  '''
  {
    [uid] => {
      [fileid] => {
        fname,
        actual file name (in FILES dir),
      }
    }
  }
  '''
} # we're using a dictionary in lieu of an actual database for simplicity's sake

# TODO: intiialize random

@app.route("/", methods=['GET'])
def index():

  return "Hello World!"

# TODO: POST /register
'''
Register will receive the client's public key

'''
@app.route('/register', methods=['POST'])
def register():

  data = request.get_json()
  if 'pubkey' not in data:
    return abort(400, "No pubkey found in json body")
  
  pubkey = RSA.importKey(b64decode(data['pubkey']))
  
  if pubkey in db['uuids'].values():
    return abort(400, "This pubkey is already registered with this server")

  uid = str(uuid4())
  while uid in db['uuids']:
    uid = str(uuid4())
  
  db['uuids'][uid] = pubkey

  contents = {
    'uid': uid,
    'iat': datetime.utcnow().timestamp(),
  }

  payload = b64encode(dumps(contents).encode('ascii'))

  h = MD5.new()
  h.update(payload)
  signature = b64encode(privkey.publickey().encrypt(h.digest(), None)[0]).decode('ascii')


  token = payload.decode('ascii') + '.' + signature

  print(db)

  return jsonify({
    'success': True,
    'token': token,
    'uid': uid,
  })

# TODO: gate methods below with an identity route that checks identities
'''
check_request:

check "Authorization" header to grab the Bearer token
(we're basically implementing OAuth1.0 for this server)
'''
# @app.before_request
# def check_request():
#   print("I am called before every request")

#   authorization = request.headers.get('Authorization')
#   if authorization is not None:
#     print(authorization)
    

def check_request(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):
    authorization = request.headers.get('Authorization')
    if authorization is None:
      return abort(403)
    print(authorization)
    # TODO: verify token here
    return f(*args, **kwargs)
  return decorated_function


# TODO: POST /token
'''
token will return tokens to clients
token format:

{
  token: <string>
}

the token value is generated using:
generate_token(payload, pubkey)
{
  uid: <string>,
  iat: <datetime>,
}
'''
@app.route('/token', methods=['POST'])
def token():
  data = request.get_json()
  if 'pubkey' not in data or 'uid' not in data:
    return abort(400, "No pubkey or uid found in json body")
  
  uid = data['uid']
  if uid not in db['uuids']:
    return abort(403, 'Uid not found in database')

  pubkey = db['uuids'][uid]

  verify = RSA.importKey(b64decode(data['pubkey']))
  if verify != pubkey:
    return abort(403, 'Pubkey does not match uid')
  
  contents = {
    'uid': str(uid),
    'iat': datetime.utcnow().timestamp(),
  }

  payload = b64encode(dumps(contents).encode('ascii'))

  h = MD5.new()
  h.update(payload)
  signature = b64encode(privkey.publickey().encrypt(h.digest(), None)[0]).decode('ascii')


  token = payload.decode('ascii') + '.' + signature

  print(db)

  return jsonify({
    'success': True,
    'token': token,
  })

# TODO: POST /upload
'''
POST /upload
checks identity
generates a fileid
'''
@app.route('/upload', methods=['POST'])
@check_request
def upload():
  if 'file' not in request.files:
    return abort(400)
  file = request.files['file']
  # if user does not select file, browser also
  # submit an empty part without filename
  if file.filename == '':
    return abort(400)
  if file:
    fileid = uuid4()

    filename = secure_filename(file.filename)
    file.save(os.path.join('files', fileid))
    return jsonify({
      'success': True,
      # fileid:?
    })

  # TODO: generate random filename

# TODO: GET /download
'''
GET /download
request using the token provided above
'''
@app.route('/download/<string:id>', methods=['GET'])
@check_request
def download(id):
  
  # TODO: get fname by id
  fname = None

  return send_file(fname)



if __name__ == '__main__':

  print("Hello")

  app.run('0.0.0.0', port=9000, debug=True)