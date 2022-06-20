from hashlib import sha256
import numpy as np

NUM_ROUNDS = 137
KEY_LEN = 16

# multiplication over GF(2^8) ~= Z2[x] / <x^8 + x^4 + x^3 + x + 1>
def gf_mul(a, b):
	c = 0
	for _ in range(8):
		if (b & 1) == 1: 
			c ^= a
		b >>= 1
		a <<= 1
		if a > 0xFF:
			a ^= 0x11B
	return c

# multiplicative inverse over GF(2^8) ~= Z2[x] / <x^8 + x^4 + x^3 + x + 1>
def gf_inv(a):
	b = 254
	c = 1
	while b > 0:
		if b & 1:
			c = gf_mul(c, a)
		b >>= 1
		a = gf_mul(a, a)
	return c

# Rijndael S-box
def sbox(a):
	x = int(gf_inv(a))
	x = x ^ (x << 1) ^ (x << 2) ^ (x << 3) ^ (x << 4) ^ 0x63
	x = (x ^ (x >> 8)) & 0xFF
	return x

# generate 176-bit expanded key
def aes_key_expansion(aes_key):
	key = bytearray(aes_key)
	c = 1
	for i in range(4 * 40):
		x = key[-16]
		if i % 16 == 0:
			x ^= sbox(key[-3]) ^ c
			c = gf_mul(c, 2)
		elif i % 16 < 3:
			x ^= sbox(key[-3])
		elif i % 16 == 3:
			x ^= sbox(key[-7])
		else:
			x ^= key[-4]
		key.append(x)
	return key

def sub_bytes(x):
	for i in range(16):
		x[i] = sbox(x[i])
	return x

def shift_rows(x):
	x[1], x[5], x[9], x[13] = x[5], x[9], x[13], x[1]
	x[2], x[6], x[10], x[14] = x[10], x[14], x[2], x[6]
	x[3], x[7], x[11], x[15] = x[15], x[3], x[7], x[11]
	return x

def mix_columns(x):
	y = bytearray.fromhex("02010103030201010103020101010302")
	z = bytearray()
	for i in range(4):
		for j in range(4):
			t = 0
			for k in range(4):
				t ^= gf_mul(x[i * 4 + k], y[k * 4 + j])
			z.append(t)
	return z

def add_round_key(x, k):
	for i in range(16):
		x[i] ^= k[i]
	return x

def aes_test(aes_plaintext, aes_key):
	expanded_key = aes_key_expansion(aes_key)
	x = bytearray(aes_plaintext)
	x = add_round_key(x, expanded_key[:16])

	for i in range(10):
		x = sub_bytes(x)
		x = shift_rows(x)
		if i < 9:
			x = mix_columns(x)
		x = add_round_key(x, expanded_key[i * 16 + 16 : i * 16 + 32])
	return bytes(x)

def hash_view(view):
	m = sha256()
	for x in view:
		m.update(x)
	return m.digest()

def generate_challenges(commitments, rounds):
	m = sha256()
	for hashed_view_tuple, y_tuple in commitments:
		for hashed_view in hashed_view_tuple:
			m.update(hashed_view)
		for y in y_tuple:
			m.update(y)

	challenges = []
	i = 0
	while len(challenges) < rounds:
		m.update(bytes(i))
		x = m.digest()[0]
		if x < 126:
			challenges.append(x % 3)
		i += 1

	return challenges

# generate rng for each three parties
def gen_rngs_tuple(key_tuple):
	return tuple(np.random.default_rng(list(key)) for key in key_tuple)

def add_tuple(x_tuple, y_tuple):
	return tuple(x ^ y for x, y in zip(x_tuple, y_tuple))

def shift_rows_tuple(x_tuple):
	return tuple(shift_rows(x) for x in x_tuple)

def mix_columns_tuple(x_tuple):
	return tuple(mix_columns(x) for x in x_tuple)

def add_round_key_tuple(x_tuple, k_tuple):
	return tuple(add_round_key(x, k) for x, k in zip(x_tuple, k_tuple))