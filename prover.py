from common import *
import pickle

if __name__ == "__main__":
	hex = ""
	while True:
		print("Enter plaintext in hex (16-byte)")
		hex = input()
		if len(hex) != 32:
			print("Must be 16-byte string")
		else:
			break
	aes_plaintext = bytearray.fromhex(hex)

	hex = ""
	while True:
		print("Enter key in hex (16-byte)")
		hex = input()
		if len(hex) != 32:
			print("Must be 16-byte string")
		else:
			break
	aes_key = bytearray.fromhex(hex)

	aes_ciphertext = aes_test(aes_plaintext, aes_key)
	print(aes_plaintext.hex(), aes_key.hex(), aes_ciphertext.hex())
	
	commitments, responses = aes_prove(aes_plaintext, aes_key)
	
	print("Enter filename for proof")
	filename = input()
	with open(filename, "wb") as f:
		pickle.dump(commitments, f)
		pickle.dump(responses, f)
	
