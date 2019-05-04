import sys
import os
from base64 import b64encode
from json import load, dump

from Crypto.PublicKey import RSA
import requests

from client import Client

SERVER_URI = 'http://0.0.0.0:9000'

if len(sys.argv) < 2:
  print('Usage: python upload.py <filename>')
  exit(0)

client = Client()

client.get_uuid()
client.get_nonce()

client.upload(sys.argv[1])

# TODO: use nonce to make request against server
# TODO: after upload store state in local state.json file

client.save()