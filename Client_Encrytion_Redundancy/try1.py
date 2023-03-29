
from eth_keys import keys
from eth_utils import keccak, encode_hex
from eth_utils import to_checksum_address

# Ethereum private key
private_key_hex = "f23a2e5c0fc265be9c572cbf11e668aa1b3a93997cdd4336ebeaa6874403f1df"

given_public_address = "0x4c4c26c72CF3D08811c5aF8945C0BDf8E3BEb694"

# Step 1: Use eth_keys library to generate a Keys object from the private key
private_key = keys.PrivateKey(bytes.fromhex(private_key_hex))

# Step 2: Get the Ethereum public key from the private key
public_key = private_key.public_key

# Step 3: Convert the public key to uncompressed format
uncompressed_public_key = public_key.to_bytes()

# Step 4: Hash the uncompressed public key using Keccak-256
hash_value = keccak(uncompressed_public_key)

# Step 5: Take the last 20 bytes of the hash value to get the Ethereum public address
public_address = encode_hex(hash_value[-20:])

checksum_address = to_checksum_address(public_address)

print("Ethereum public address:", public_address)

print(checksum_address)

print(given_public_address == checksum_address)
