from common import *
import sys

def verify_distribute(length, e_tuple, rng_tuple, view_tuple, view_idx):
	if view_idx >= len(view_tuple[0]) or view_idx >= len(view_tuple[1]):
		return None, None, False
	x0 = view_tuple[0][view_idx]
	x1 = view_tuple[1][view_idx]
	view_idx += 1

	if e_tuple[0] < 2 and x0 != rng_tuple[0].bytes(length):
		return None, None, False
	if e_tuple[1] < 2 and x1 != rng_tuple[1].bytes(length):
		return None, None, False
	
	return (x0, x1), view_idx, True

def verify_add_round_key(x_tuple, k_tuple):
	return tuple(add_round_key(x, k) for x, k in zip(x_tuple, k_tuple))

def verify_mul(x_tuple, y_tuple, rng_tuple, view_tuple, view_idx):
	if view_idx >= len(view_tuple[0]) or view_idx >= len(view_tuple[1]):
		return None, None, False

	r_tuple = tuple(rng.integers(256) for rng in rng_tuple)
	z0 = gf_mul(x_tuple[0], y_tuple[0]) \
		^ gf_mul(x_tuple[1], y_tuple[0]) \
		^ gf_mul(x_tuple[0], y_tuple[1]) \
		^ r_tuple[0] ^ r_tuple[1]
	if z0 != view_tuple[0][view_idx]:
		return None, None, False
	z1 = view_tuple[1][view_idx]
	view_idx += 1

	return (z0, z1), view_idx, True

def verify_inv(x_tuple, rng_tuple, view_tuple, view_idx):
	b = 254
	y_tuple = (1, 1, 1)
	while b > 0:
		if b & 1:
			y_tuple, view_idx, valid = verify_mul(x_tuple, y_tuple, rng_tuple, view_tuple, view_idx)
			if not valid:
				return None, None, False
		b >>= 1
		x_tuple, view_idx, valid = verify_mul(x_tuple, x_tuple, rng_tuple, view_tuple, view_idx)
		if not valid:
			return None, None, False
	return y_tuple, view_idx, True

def verify_sbox(x_tuple, rng_tuple, view_tuple, view_idx):
	x_tuple, view_idx, valid = verify_inv(x_tuple, rng_tuple, view_tuple, view_idx)
	if not valid:
		return None, None, False
	y = []
	for x in x_tuple:
		x = x ^ (x << 1) ^ (x << 2) ^ (x << 3) ^ (x << 4) ^ 0x63
		x = (x ^ (x >> 8)) & 0xFF
		y.append(x)
	return tuple(y), view_idx, True

def verify_sub_bytes(x_tuple, rng_tuple, view_tuple, view_idx):
	for i in range(16):
		y_tuple = (x_tuple[0][i], x_tuple[1][i])
		y_tuple, view_idx, valid = verify_sbox(y_tuple, rng_tuple, view_tuple, view_idx)
		if not valid:
			return None, None, False
		x_tuple[0][i], x_tuple[1][i] = y_tuple
	return x_tuple, view_idx, True

def verify_key_expansion(key_tuple, e_tuple, rng_tuple, view_tuple, view_idx):
	expanded_key_tuples = [key_tuple]
	key_byte_tuples = [tuple(key[i] for key in key_tuple) for i in range(16)]
	_key_tuple = (bytearray(), bytearray())
	c = 1
	for i in range(4 * 40):
		x_tuple = tuple(key_byte_tuples[-16])
		if i % 16 == 0 :
			if e_tuple[0] == 0:
				x_tuple = (x_tuple[0] ^ c, x_tuple[1])
			elif e_tuple[1] == 0:
				x_tuple = (x_tuple[0], x_tuple[1] ^ c)
			c = gf_mul(c, 2)
		y_tuple, view_idx, valid = \
				verify_sbox(key_byte_tuples[-3], rng_tuple, view_tuple, view_idx) if i % 16 < 3 else \
				verify_sbox(key_byte_tuples[-7], rng_tuple, view_tuple, view_idx) if i % 16 == 3 else \
				(key_byte_tuples[-4], view_idx, True)
		if not valid:
			return None, None, False
		
		x_tuple = add_tuple(x_tuple, y_tuple)
		key_byte_tuples.append(x_tuple)

		for j in range(2):
			_key_tuple[j].append(x_tuple[j])
		if i % 16 == 15:
			expanded_key_tuples.append(_key_tuple)
			_key_tuple = (bytearray(), bytearray())
	return expanded_key_tuples, view_idx, True

def aes_verify_round(aes_plaintext, aes_ciphertext, hashed_view_tuple, y_tuple, e, response):
	if len(y_tuple[0]) != len(aes_ciphertext) or len(y_tuple[1]) != len(aes_ciphertext) or len(y_tuple[2]) != len(aes_ciphertext):
		return False
	for i in range(len(aes_ciphertext)):
		if y_tuple[0][i] ^ y_tuple[1][i] ^ y_tuple[2][i] != aes_ciphertext[i]:
			return False
	
	k0, w0, k1, w1 = response
	e0, e1 = e, (e + 1) % 3
	if hash_view(w0) != hashed_view_tuple[e0] or hash_view(w1) != hashed_view_tuple[e1]:
		return False

	rng_tuple = gen_rngs_tuple((k0, k1))
	view_tuple = (w0, w1)
	view_idx = 0
	e_tuple = (e0, e1)

	x_tuple = (bytearray(aes_plaintext), bytearray(16), bytearray(16))
	x_tuple = (x_tuple[e0], x_tuple[e1])

	key_tuple, view_idx, valid = verify_distribute(16, e_tuple, rng_tuple, view_tuple, view_idx)
	if not valid:
		return False
	expanded_key_tuples, view_idx, valid = verify_key_expansion(key_tuple, e_tuple, rng_tuple, view_tuple, view_idx)
	if not valid:
		return False

	x_tuple = verify_add_round_key(x_tuple, expanded_key_tuples[0])
	for i in range(10):
		x_tuple, view_idx, valid = verify_sub_bytes(x_tuple, rng_tuple, view_tuple, view_idx)
		if not valid:
			return False
		x_tuple = shift_rows_tuple(x_tuple)
		if i < 9:
			x_tuple = mix_columns_tuple(x_tuple)
		x_tuple = verify_add_round_key(x_tuple, expanded_key_tuples[i + 1])
	
	if not (view_idx == len(w0) and view_idx == len(w1)):
		return False
	
	return True

def aes_verify(aes_plaintext, aes_ciphertext, commitments, responses):
	challenges = generate_challenges(commitments, NUM_ROUNDS)
	for i in range(NUM_ROUNDS):
		sys.stdout.write("> Round %03d" % i)
		sys.stdout.flush()

		hashed_view_tuple, y_tuple = commitments[i]
		if not aes_verify_round(aes_plaintext, aes_ciphertext, hashed_view_tuple, y_tuple, challenges[i], responses[i]):
			return False

		sys.stdout.write("\b" * 12)
		sys.stdout.flush()
	return True