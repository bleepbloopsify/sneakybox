
# Usage:

We used virtual environments to setup custom environments for each client and server


## Client

`$ cd client`
`$ python3 -m venv env`
`$ source env/bin/activate`
`$ pip install -r requirements.txt`

The client allows you to upload/download files from server

`$ python upload.py <filename>`
`$ python download.py <file_id/filename>`

## Server
`$ cd server`
`$ python3 -m venv env`
`$ source env/bin/activate`
`$ pip install -r requirements.txt`

The server serves locally. Make sure port 9000 is open

`$ python app.py`