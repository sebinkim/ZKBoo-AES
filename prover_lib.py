from common import *
import sys

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

def mpc_key_expansion(key_tuple, rng_tuple, view_tuple):
	expanded_key_tuples = [key_tuple]
	key_byte_tuples = [tuple(key[i] for key in key_tuple) for i in range(16)]
	_key_tuple = (bytearray(), bytearray(), bytearray())
	c = 1
	for i in range(4 * 40):
		x_tuple = tuple(key_byte_tuples[-16])
		if i % 16 == 0 :
			x_tuple = (x_tuple[0] ^ c, x_tuple[1], x_tuple[2])
			c = gf_mul(c, 2)
		y_tuple = mpc_sbox(key_byte_tuples[-3], rng_tuple, view_tuple) if i % 16 < 3 else \
				  mpc_sbox(key_byte_tuples[-7], rng_tuple, view_tuple) if i % 16 == 3 else \
				  key_byte_tuples[-4]
		x_tuple = add_tuple(x_tuple, y_tuple)
		key_byte_tuples.append(x_tuple)

		for j in range(3):
			_key_tuple[j].append(x_tuple[j])
		if i % 16 == 15:
			expanded_key_tuples.append(_key_tuple)
			_key_tuple = (bytearray(), bytearray(), bytearray())
	return expanded_key_tuples

def aes_generate_commitment(keys, aes_plaintext, aes_key):
	rng_tuple = gen_rngs_tuple(keys)
	view_tuple = ([], [], [])

	x = bytearray(aes_plaintext)
	key_tuple = mpc_distribute(aes_key, 16, rng_tuple, view_tuple)
	expanded_key_tuples = mpc_key_expansion(key_tuple, rng_tuple, view_tuple)
	
	x_tuple = (x, bytearray(16), bytearray(16))

	x_tuple = add_round_key_tuple(x_tuple, expanded_key_tuples[0])
	for i in range(10):
		x_tuple = mpc_sub_bytes(x_tuple, rng_tuple, view_tuple)
		x_tuple = shift_rows_tuple(x_tuple)
		if i < 9:
			x_tuple = mix_columns_tuple(x_tuple)
		x_tuple = add_round_key_tuple(x_tuple, expanded_key_tuples[i + 1])

	return view_tuple, x_tuple

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

	# Debugging
	'''
	print("<Commitments>")
	print(commitments)
	print("<Challenges>")
	print(challenges)
	print("<Responses>")
	print(responses)	
	'''
	return (commitments, responses)