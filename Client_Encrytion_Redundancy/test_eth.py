from eth_keys import keys
from eth_utils import keccak, encode_hex, decode_hex
from eth_utils import to_checksum_address
from Crypto.PublicKey import ECC
from py_ecc import optimized_bls12_381 as b

from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.ellipticcurve import Point

def gen_eth_private_key():
  """
  This function is to generate ethereum private key
  """
  private_key = ECC.generate(curve='P-256')
  private_key_hex = private_key.export_key(format='DER', use_pkcs8=False).hex()[:64]
  print("Private key: ", private_key_hex)
  return private_key

def gen_eth_public_key(private_key):
  """
  This function is to generate ethereum public key given a private key
  """
  private_key = keys.PrivateKey(bytes.fromhex(private_key[2:]))
  public_key = private_key.public_key
  return public_key

def gen_eth_public_address(public_key):
  """
  This function is used to generate the ethereum public address based on its public key
  """
  # Step 1: Convert the public key to uncompressed format
  uncompressed_public_key = public_key.to_bytes()
  # Step 2: Hash the uncompressed public key using Keccak-256
  hash_value = keccak(uncompressed_public_key)
  # Step 3: Take the last 20 bytes of the hash value to get the Ethereum public address
  public_address = encode_hex(hash_value[-20:])
  checksum_address = to_checksum_address(public_address)
  return checksum_address


def varify_eth_keypair(given_private_key, given_public_addr):
  """
  This function is used to verify whether the 
  (public address, private key) is a valid pair in ethereum.
  """
  public_key = gen_eth_public_key(given_private_key)
  public_addr = gen_eth_public_address(public_key)
  print(public_addr == given_public_addr)



def gen_shared_secret(sender_sk_hex, receiver_pk_hex):
    """
    This function is to generate a shared secret between the sender and the receiver using the sender's secret key and the receiver's public key
    """
    # Convert the sender's secret key and receiver's public key from hex to int
    sender_sk_int = int(sender_sk_hex, 16)
    receiver_pk_int = int(receiver_pk_hex, 16)

    # Create SigningKey and VerifyingKey objects
    sender_sk = SigningKey.from_secret_exponent(sender_sk_int, curve=SECP256k1)
    receiver_pk = VerifyingKey.from_string(receiver_pk_int.to_bytes(64, byteorder='big'), curve=SECP256k1)

    # Get the elliptic curve point of the receiver's public key
    receiver_pk_point = Point(SECP256k1.curve, receiver_pk.pubkey.point.x(), receiver_pk.pubkey.point.y())

    # Calculate the shared secret point by multiplying the sender's secret key with the receiver's public key point
    shared_secret_point = sender_sk.privkey.secret_multiplier * receiver_pk_point

    # Convert the x-coordinate of the shared secret point to bytes
    shared_secret_bytes = shared_secret_point.x().to_bytes(32, byteorder='big')

    return shared_secret_bytes

  
if __name__ == "__main__":

  ##########
  ## sample key pairs:
  ## neo given 1-3 for testing
  public_addr_1 = "0xD4cdE7b7480CC3228D3725FB1b8D8d4226267bA3"
  private_key_1 = "0x7004f17e0cab05642f36e8ddb30b778c4ba5b6d2bc2a17338aaff3b26c55e241"
  public_key_1 = "0x47d9eab50b1eabd3f493e807ba3ff22f387dcf146430e31f42c98b7ec7fbc9a40eef2080249846ca63521da29f0bcaa2049a0105cbd865d91973059a10d00daa"
  ##----------------
  public_addr_2 =  "0x290FABa2538A49e641e92f330CCA5afc1Ff2076C"
  private_key_2 =  "0xb6c5753277f0f69e8f66196293772ce624d90a58edbfd9275ec426744ecd2dcf"           
  public_key_2 = "0xa4c6fcffb1411ba3c5335f9971114603d4c58f3b53e149f1a78128de50f475f2a2b22b780c9a94c83e4de662f54fd826a239633a0e3cb0c4537f591a70a386c0"
  ##----------------
  public_addr_3 = "0x58148928Cc24aA0f4025F171cDF958eA24143211"
  private_key_3 = "0x4a561ed4832e2787355f63010ffa05453bf190b7f50b5aa8d01433a6a4fbe67a"
  public_key_3 = "0x583f3823024eff1d6c19cd93a4b8fb48a3bd2d8e868ddcc26ffa99553046bbf77eb1fdb85d463b73d639ad395c7c7307d29510c1781032ef450c739d8415b1cc"
  ## ---------------
  ## 4 is generate by me
  private_key_4 = "0x3077020101042085af18963da3c5ae8e1b3f5315769048a1dd604968a3605fb9"
  public_key_4 ="0xaf1e8c0521f5bc7ce85a3b4c2e312cc2458b62db3f0a7660c285abaa77dc09d4d83a34074648e077ad9f1f217ce23921c47e5e0d7920ef6d5087f9a9bdb6fd59"
  public_addr_4 ="0x28AbB50DdB82da709E2e47Eef2ECAdAC5e230e83"
  
  #gen_eth_private_key()
  #varify_eth_keypair(private_key, public_addr)
  #public_key_1 = gen_eth_public_key(private_key_1)
  #public_key_2 = gen_eth_public_key(private_key_2)
  #public_key_3 = gen_eth_public_key(private_key_3)
  #print(public_key_1)
  #print(public_key_2)
  #print(public_key_3)
  #private_key_4 = gen_eth_private_key()
  #public_key_4 = gen_eth_public_key(private_key_4)
  #public_addr_4 = gen_eth_public_address(public_key_4)
  # print(private_key_4)
  # print(public_key_4)
  # print(public_addr_4)
  #varify_eth_keypair(private_key_4, public_addr_4)
  
  print(gen_shared_secret(private_key_3[2:], public_key_2[2:]) == gen_shared_secret(private_key_2[2:], public_key_3[2:]))
  print(gen_shared_secret(private_key_3[2:], public_key_1[2:]) == gen_shared_secret(private_key_1[2:], public_key_3[2:]))
  print(gen_shared_secret(private_key_2[2:], public_key_1[2:]) == gen_shared_secret(private_key_1[2:], public_key_2[2:]))
  print(gen_shared_secret(private_key_4[2:], public_key_1[2:]) == gen_shared_secret(private_key_1[2:], public_key_4[2:]))
  print(gen_shared_secret(private_key_4[2:], public_key_2[2:]) == gen_shared_secret(private_key_2[2:], public_key_4[2:]))
  print(gen_shared_secret(private_key_4[2:], public_key_3[2:]) == gen_shared_secret(private_key_3[2:], public_key_4[2:]))


  
  

