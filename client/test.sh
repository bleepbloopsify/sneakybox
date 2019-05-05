#!/bin/bash

fileid=$(python upload.py test.txt)

python download.py $fileid

# python download.py 