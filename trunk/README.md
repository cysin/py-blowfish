Python blowfish implementation
=====================
blueflycn@gmail.com

To build:
 # python setup.py build

Install
 # python setup.py install

Samples:

import blowfish
key = blowfish.genkey('12345')   #generate secret key
encrypted = blowfish.encrypt(key, 'Hello world')   #encrypt with key
decrypted = blowfish.decrypt(key, encrypted)   #decrypt with key
print decrypted
