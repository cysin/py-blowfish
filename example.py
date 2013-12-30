import blowfish
key = blowfish.genkey('12345')   #generate secret key
encrypted = blowfish.encrypt(key, 'Hello world')   #encrypt with key
decrypted = blowfish.decrypt(key, encrypted)   #decrypt with key
print decrypted

