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
		print("Enter ciphertext in hex (16-byte)")
		hex = input()
		if len(hex) != 32:
			print("Must be 16-byte string")
		else:
			break
	aes_ciphertext = bytearray.fromhex(hex)

	print("Enter filename for proof")
	filename = input()
	with open(filename, "rb") as f:
		commitments = pickle.load(f)
		responses = pickle.load(f)

		print("Accepted" if aes_verify(aes_plaintext, aes_ciphertext, commitments, responses) else "Rejected")
	
