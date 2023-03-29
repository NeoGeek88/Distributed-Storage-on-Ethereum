from eth_keys import keys
from eth_utils import keccak, encode_hex
from eth_utils import to_checksum_address

def gen_eth_public_key(private_key):
	private_key = keys.PrivateKey(bytes.fromhex(private_key[2:]))
	public_key = private_key.public_key
	return public_key

def gen_eth_public_address(public_key):
	# Step 3: Convert the public key to uncompressed format
	uncompressed_public_key = public_key.to_bytes()
	# Step 4: Hash the uncompressed public key using Keccak-256
	hash_value = keccak(uncompressed_public_key)
	# Step 5: Take the last 20 bytes of the hash value to get the Ethereum public address
	public_address = encode_hex(hash_value[-20:])
	checksum_address = to_checksum_address(public_address)
	return checksum_address

def test(given_private_key, given_public_addr):
	public_key = gen_eth_public_key(given_private_key)
	public_addr = gen_eth_public_address(public_key)
	print(public_addr == given_public_addr)

# public_addr = "0xD4cdE7b7480CC3228D3725FB1b8D8d4226267bA3"
# private_key = "0x7004f17e0cab05642f36e8ddb30b778c4ba5b6d2bc2a17338aaff3b26c55e241"

# public_addr =  "0x290FABa2538A49e641e92f330CCA5afc1Ff2076C"
# private_key =  "0xb6c5753277f0f69e8f66196293772ce624d90a58edbfd9275ec426744ecd2dcf"

public_addr = "0x58148928Cc24aA0f4025F171cDF958eA24143211"
private_key = "0x4a561ed4832e2787355f63010ffa05453bf190b7f50b5aa8d01433a6a4fbe67a"
test(private_key, public_addr)
