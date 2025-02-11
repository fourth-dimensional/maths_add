#encoding:utf-8
from maths_add.except_error import decorate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

private_key=rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
public_key=private_key.public_key()

@decorate
def encode(message):
	encrypted=public_key.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
	return encrypted

@decorate
def decode(message):
	decrypted=private_key.decrypt(encrypted,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
	return decrypted

@decorate
def savePrivate_Key(FilePath):
	with open(FilePath,"w") as f:
		f.write(private_key)

@decorate
def savePublic_Key(FilePath):
	with open(FilePath,"w") as f:
		f.write(public_key)

@decorate
def saveEncodeFile(FilePath,encrypted):
	with open(FilePath,"w") as f:
		f.write(encrypted)

@decorate
def saveDecodeFile(FilePath,decrypted):
	with open(FilePath,"w") as f:
		f.write(decrypted)
