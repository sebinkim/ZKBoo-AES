from prover_lib import aes_prove
from common import aes_test
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
		print("Enter key in hex (16-byte): ", end='')
		hex = input()
		if len(hex) != 32:
			print("Must be 16-byte string")
		else:
			break
	aes_key = bytearray.fromhex(hex)

	aes_ciphertext = aes_test(aes_plaintext, aes_key)

	print()
	print("Plaintext:", aes_plaintext.hex())
	print("Key:", aes_key.hex())
	print("Ciphertext:", aes_ciphertext.hex())
	
	print()
	print("Enter filename for proof: ", end='')
	filename = input()
	print()

	st = datetime.now()
	commitments, responses = aes_prove(aes_plaintext, aes_key)
	en = datetime.now()
	
	with open(filename, "wb") as f:
		pickle.dump(commitments, f)
		pickle.dump(responses, f)

	print("\n")
	print("Proof generated in", filename)
	print(round((en - st).total_seconds() * 1000, 3), "ms")
	
