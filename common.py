from hashlib import sha256
import sys
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

# generate rng for each three parties
def mpc_gen_rngs(keys):
	return tuple(np.random.default_rng(list(key)) for key in keys)

# distribute x among the three parties
# i.e. generate x0, x1, x2 s.t. x0 + x1 + x2 = x
# x: bytearray with length `length'`
def mpc_distribute(x, length, rng_tuple, view_tuple):
	x0 = bytearray(rng_tuple[0].bytes(length))
	x1 = bytearray(rng_tuple[1].bytes(length))
	x2 = bytearray()
	for i in range(length):
		x2.append(x[i] ^ x0[i] ^ x1[i])
	view_tuple[0].append(x0)
	view_tuple[1].append(x1)
	view_tuple[2].append(x2)
	return (x0, x1, x2)

def mpc_mul(x_tuple, y_tuple, rng_tuple, view_tuple):
	r_tuple = tuple(rng.integers(256) for rng in rng_tuple)
	z = []
	for i in range(3):
		t = gf_mul(x_tuple[i], y_tuple[i]) \
			^ gf_mul(x_tuple[(i + 1) % 3], y_tuple[i]) \
			^ gf_mul(x_tuple[i], y_tuple[(i + 1) % 3]) \
			^ r_tuple[i] ^ r_tuple[(i + 1) % 3]
		z.append(t)
		view_tuple[i].append(t)
	return tuple(z)

def mpc_inv(x_tuple, rng_tuple, view_tuple):
	b = 254
	y_tuple = (1, 1, 1)
	while b > 0:
		if b & 1:
			y_tuple = mpc_mul(x_tuple, y_tuple, rng_tuple, view_tuple)
		b >>= 1
		x_tuple = mpc_mul(x_tuple, x_tuple, rng_tuple, view_tuple)
	return y_tuple

def mpc_sbox(x_tuple, rng_tuple, view_tuple):
	x_tuple = mpc_inv(x_tuple, rng_tuple, view_tuple)
	y = []
	for x in x_tuple:
		x = x ^ (x << 1) ^ (x << 2) ^ (x << 3) ^ (x << 4) ^ 0x63
		x = (x ^ (x >> 8)) & 0xFF
		y.append(x)
	return tuple(y)

def mpc_sub_bytes(x_tuple, rng_tuple, view_tuple):
	for i in range(16):
		(x_tuple[0][i], x_tuple[1][i], x_tuple[2][i]) = mpc_sbox((x_tuple[0][i], x_tuple[1][i], x_tuple[2][i]), rng_tuple, view_tuple)
	return x_tuple

def mpc_shift_rows(x_tuple):
	return tuple(shift_rows(x) for x in x_tuple)

def mpc_mix_columns(x_tuple):
	return tuple(mix_columns(x) for x in x_tuple)

def mpc_add_round_key(x_tuple, key, rng_tuple, view_tuple):
	k_tuple = mpc_distribute(key, 16, rng_tuple, view_tuple)
	return tuple(add_round_key(x, k) for x, k in zip(x_tuple, k_tuple))

def aes_generate_commitment(keys, aes_plaintext, aes_key):
	rng_tuple = mpc_gen_rngs(keys)
	view_tuple = ([], [], [])

	x = bytearray(aes_plaintext)
	expanded_key = aes_key_expansion(aes_key)
	
	x_tuple = (x, bytearray(16), bytearray(16))

	x_tuple = mpc_add_round_key(x_tuple, expanded_key[:16], rng_tuple, view_tuple)
	for i in range(10):
		x_tuple = mpc_sub_bytes(x_tuple, rng_tuple, view_tuple)
		x_tuple = mpc_shift_rows(x_tuple)
		if i < 9:
			x_tuple = mpc_mix_columns(x_tuple)
		x_tuple = mpc_add_round_key(x_tuple, expanded_key[i * 16 + 16 : i * 16 + 32], rng_tuple, view_tuple)

	return view_tuple, x_tuple

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

def aes_prove(aes_plaintext, aes_key):
	keys, views, commitments = [], [], []
	for i in range(NUM_ROUNDS):
		sys.stdout.write("> Round %03d" % i)
		sys.stdout.flush()

		# generate random keys for three parties
		k = tuple(np.random.bytes(KEY_LEN) for _ in range(3))
		keys.append(k)

		# generate views for three parties
		view_tuple, y_tuple = aes_generate_commitment(k, aes_plaintext, aes_key)
		views.append(view_tuple)

		# generate commitments
		hashed_view_tuple = tuple(hash_view(v) for v in view_tuple)
		commitments.append((hashed_view_tuple, y_tuple))

		sys.stdout.write("\b" * 12)
		sys.stdout.flush()
	
	challenges = generate_challenges(commitments, NUM_ROUNDS)

	responses = []
	for k, w, e in zip(keys, views, challenges):
		responses.append((k[e], w[e], k[(e + 1) % 3], w[(e + 1) % 3]))

	return (commitments, responses)

verify_gen_rngs = mpc_gen_rngs
verify_shift_rows = mpc_shift_rows
verify_mix_columns = mpc_mix_columns

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

def verify_add_round_key(x_tuple, e_tuple, rng_tuple, view_tuple, view_idx):
	k_tuple, view_idx, valid = verify_distribute(16, e_tuple, rng_tuple, view_tuple, view_idx)
	if not valid:
		return None, None, False
	return tuple(add_round_key(x, k) for x, k in zip(x_tuple, k_tuple)), view_idx, True

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

	rng_tuple = verify_gen_rngs((k0, k1))
	view_tuple = (w0, w1)
	view_idx = 0
	e_tuple = (e0, e1)

	x_tuple = (bytearray(aes_plaintext), bytearray(16), bytearray(16))
	x_tuple = (x_tuple[e0], x_tuple[e1])

	x_tuple, view_idx, valid = verify_add_round_key(x_tuple, e_tuple, rng_tuple, view_tuple, view_idx)
	if not valid:
		return False
	for i in range(10):
		x_tuple, view_idx, valid = verify_sub_bytes(x_tuple, rng_tuple, view_tuple, view_idx)
		if not valid:
			return False
		x_tuple = verify_shift_rows(x_tuple)
		if i < 9:
			x_tuple = verify_mix_columns(x_tuple)
		x_tuple, view_idx, valid = verify_add_round_key(x_tuple, e_tuple, rng_tuple, view_tuple, view_idx)
		if not valid:
			return False
	
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