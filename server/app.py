from flask import Flask

app = Flask(__name__)

@app.route("/", methods=['GET'])
def index():

  return "Hello World!"

# TODO: POST /register
'''
Register will receive the client's public key

'''

# TODO: POST /token
'''
token will return tokens to clients
token format:
{
  uid: <string>,
  iat: <datetime>,
}

'''


if __name__ == '__main__':

  print("Hello")

  app.run('0.0.0.0', port=9000)