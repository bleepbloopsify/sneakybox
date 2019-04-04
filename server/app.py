from uuid import uuid4

from flask import Flask, jsonify
from Crypto.Cipher import AES
from Crypto import Random

app = Flask(__name__)
db = {} # we're using a dictionary in lieu of an actual database for simplicity's sake

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

  # TODO: get pubkey from form-body or json post data

  # TODO: generate token here
  token = None

  return jsonify({
    success: True,
    token: token,
  })

# TODO: gate methods below with an identity route that checks identities
'''
check_request:

check "Authorization" header to grab the Bearer token
(we're basically implementing OAuth1.0 for this server)
'''


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
  uid = uuid4()

  payload = {
    
  }

  token = None

  return jsonify({
    success: True,
    token: token,
  })

# TODO: POST /upload
'''
POST /upload
checks identity
generates a fileid
'''
@app.route('/upload', methods=['POST'])
def upload():
  fileid = uuid4()

  # TODO: generate random filename

  return jsonify({
    success: True,
    fileid:
  })

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

  app.run('0.0.0.0', port=9000)