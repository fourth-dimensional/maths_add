#encoding:utf-8
from maths_add.except_error import decorate
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes

key=get_random_bytes(16)
iv=get_random_bytes(16)

@decorate
def encode(plaintext):
	cipher=AES.new(key,AES.MODE_CBC,iv)
	ciphertext=cipher.encrypt(pad(plaintext,AES.block_size))
	return ciphertext

@decorate
def decode(ciphertext):
	decipher=AES.new(key,AES.MODE_CBC,iv)
	decrypted_text=unpad(decipher.decrypt(ciphertext),AES.block_size)
	return decrypted_text

@decorate
def saveKey(FilePath):
	with open(FilePath,"w") as f:
		f.write(key)

@decorate
def saveEncodeFile(FilePath,plaintext):
	with open(FilePath,"w") as f:
		f.write(plaintext)

@decorate
def saveDecodeFile(FilePath,ciphertext):
	with open(FilePath,"w") as f:
		f.write(ciphertext)

if __name__ == '__main__':
	print(encode(bytes(545)))