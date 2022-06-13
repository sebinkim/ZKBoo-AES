from common import *
import pickle
from datetime import datetime

if __name__ == "__main__":
	hex = ""
	while True:
		print("Enter plaintext in hex (16-byte): ", end='')
		hex = input()
		if len(hex) != 32:
			print("Must be 16-byte string")
		else:
			break
	aes_plaintext = bytearray.fromhex(hex)

	hex = ""
	while True:
		print("Enter ciphertext in hex (16-byte): ", end='')
		hex = input()
		if len(hex) != 32:
			print("Must be 16-byte string")
		else:
			break
	aes_ciphertext = bytearray.fromhex(hex)

	print()
	print("Plaintext:", aes_plaintext.hex())
	print("Ciphertext:", aes_ciphertext.hex())

	print()
	print("Enter filename for proof: ", end='')
	filename = input()
	print()

	with open(filename, "rb") as f:
		commitments = pickle.load(f)
		responses = pickle.load(f)

		st = datetime.now()
		accepted = aes_verify(aes_plaintext, aes_ciphertext, commitments, responses)
		en = datetime.now()
		

		print("\n")
		print("Accepted" if accepted else "Rejected")
		print(round((en - st).total_seconds() * 1000, 3), "ms")
	
