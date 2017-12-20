#!/usr/bin/python

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os
import binascii
import cPickle
import datetime
import hashlib

ts = 'Timestamp: {:%Y-%m-%d %H:%M}'.format(datetime.datetime.now())

key = binascii.hexlify(os.urandom(16))

R = '12345'
X = '12'
print X

#h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h = hashlib.sha512()
h.update(R+ X + ts)
#puzzle = h.finalize()
puzzle =  h.hexdigest()

#puzzle = binascii.hexlify(puzzle)
print puzzle

h.update(R+ X + ts)
puzzle2 = h.hexdigest()

print puzzle2


X1 = 0
answer = '0'

while puzzle != answer:
 #   h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    X1 = int(X1)
    X1 = X1 + 1
    X1 = str(X1)
    h.update(R + X1 + ts)
 #   answer = binascii.hexlify(h.finalize())
    answer = h.hexdigest()

print X1
print answer







