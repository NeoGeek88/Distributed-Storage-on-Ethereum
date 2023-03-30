# -*- coding: utf-8 -*-
"""try5_ipynb.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/github/NeoGeek88/Distributed-Storage-on-Ethereum/blob/yoyostudy/Client_Encrytion_Redundancy/try5_ipynb.ipynb
"""


from eth_keys import keys
from eth_utils import keccak, encode_hex, decode_hex
from eth_utils import to_checksum_address

"""Generate Ethereum key pair: Public Key, Private Key, Public Address and verify it."""

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
  private_key = keys.PrivateKey(bytes.fromhex(private_key))
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

"""Obtain the shared secret using the receiver's public key and the sender's private key"""

# !pip3 install pycryptodome
# !pip3 install py_ecc
# !pip3 install ecdsa

from Crypto.PublicKey import ECC
from py_ecc import optimized_bls12_381 as b
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.ellipticcurve import Point

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

def test_shared_secret(sender_pk, sender_sk, receiver_pk, receiver_sk):
  print( gen_shared_secret(sender_sk, receiver_pk) == gen_shared_secret(receiver_sk, sender_pk))

"""Generate AES encryption key and MAC key based on the shared secret"""

# !pip3 install cryptography

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

def gen_aes_mac_key(shared_secret):
  """
  This function is to generate the aes encryption key and the mac key using the shared secret
  Method:
    KDF
  Parameter:
    shared_secret 32 bytes (256 bit)
  Returns:
    aes_key: 32 bytes
    mac_key: 32 bytes
  """
  # Derive encryption and MAC keys using HKDF
  kdf = HKDF(
      algorithm=hashes.SHA256(),
      length=64,  # Total length of the derived keys (in bytes)
      salt=None,
      info=b'my key derivation info',
  )

  # Generate encryption and MAC keys
  derived_key = kdf.derive(shared_secret)
  aes_key = derived_key[:32]  # 256-bit key for encryption
  mac_key = derived_key[32:]  # 256-bit key for message authentication code (MAC)
  return aes_key, mac_key

"""Encrypt the ata chunk usinig symmetric encryption, the encryption key is the aes key I generated by the shared secret"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_enc(chunk, aes_key):
    """
    This function is to encrypt the data chunk using the 256 bit aes_key
    Method:
      CBC-AES block cipher + #PKCS#7 padding + 16 zero bytes IV
    Parameters:
      chunk
      aes_key 256 bit
    Returns:
      enc_chunk (chunk of padded size)
    """
    backend = default_backend()
    iv = bytes(16)  # use a zero byte IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    # apply PKCS#7 padding to the plaintext data
    padded_chunk = chunk + (16 - len(chunk) % 16) * chr(16 - len(chunk) % 16).encode()
    enc_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
    return enc_chunk  # return the encrypted data only

def aes_dec(enc_chunk, aes_key):
  """
  This function is to decrypt the data chunk using the 256 bit aes_key
  Method:
    CBC-AES block cipher + #PKCS#7 padding + 16 zero bytes IV
  Parameters:
    enc_chunk (chunk of padded size)
    aes_key 256 bit
  Returns:
    plaintext: original chunk data (size = the original chunk data)
  """
  backend = default_backend()
  iv = bytes(16)  # use a zero byte IV
  cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
  decryptor = cipher.decryptor()
  # decrypt the ciphertext and remove any added padding
  padded_plaintext = decryptor.update(enc_chunk) + decryptor.finalize()
  plaintext = padded_plaintext[:-padded_plaintext[-1]]
  return plaintext

def test_aes_encryption(chunk, aes_key):
  enc_chunk = aes_enc(chunk, aes_key)
  dec_chunk = aes_dec(enc_chunk, aes_key)
  print(dec_chunk == chunk)

"""Generation and Verification of MAC tag"""

import hmac

def gen_mac_tag(message, mac_key):
  """
  This function is to generate mac tag for message integrity.
  More precisely, we need to check the encyrpted data is tampered or not during communication
  In this case, we can use mac tag and verification funciton to check
  Method:
    HAMC-SHA256
  Parameters:
     message
     mac_key 32bytes
  Returns:
     mac_tag 32bytes
  """
  mac = hmac.new(mac_key, msg=message, digestmod="sha256")
  mac_tag = mac.digest()
  return mac_tag

def ver_mac_tag(message, mac_tag, mac_key):
  """
  This function is to verify the mac tag for message integrity
  Method:
    HAMC-SHA256
  Parameters:
     message
     mac_tag 32bytes
  Returns:
     mac_key 32bytes
  """
  new_mac_tag = gen_mac_tag(message, mac_key)
  return hmac.compare_digest(mac_tag, new_mac_tag)

def test_mac(enc_chunk, mac_key):
  old_mac_tag = gen_mac_tag(enc_chunk, mac_key)
  print(ver_mac_tag(enc_chunk, old_mac_tag, mac_key))


def split(fileBytearray, chunkSize):
    """
    Padding
    Chunks (List[bytearray]), each chunk has length = chunksize
    """
    chunk_list = [ bytearray(fileBytearray[i:i+chunkSize])for i in range(0, len(fileBytearray), chunkSize)]
    if chunk_list:
        remain_bytes = chunkSize-len(chunk_list[-1])
        chunk_list[-1].extend(bytearray(remain_bytes))
    return chunk_list

def combine(self, chunkList):
    """
    strip end 0s
    chunkList (List[bytearray]+padding) --> data (bytearray)
    """
    data = bytearray()
    for chunk in chunkList:
        data.extend(chunk)
    data = data.rstrip(b'\x00')
    return data

class file_handler():

  def __init__(self):
    pass

  def uploader_helper(self, file_content, sender_sk, receiver_pk, chunkSize = 262144):
    """
    Parameters:
      file_content : bytearray
      sender_sk
      receiver_pk
      chunkSize: 262144 (256 KB) # you can also modify it
    """
    #1. generate shared secret between the sender and the receiver
    shared_secret = gen_shared_secret(sender_sk, receiver_pk)
    #2. obtain the encryption key and the mac key
    enc_key, mac_key = gen_aes_mac_key(shared_secret)
    #3. split the data into chunks
    chunk_list = split(file_content, chunkSize)
    #4. encrypt the file content using the encryption key
    enc_data_list = [aes_enc(chunk, enc_key) for chunk in chunk_list]
    #5. redundancy || NOT COMPLETE
    rs_data_list = enc_data_list
    #6. generate mac tag for each of the data chunk
    mac_tag_list = [gen_mac_tag(chunk, mac_key) for chunk in rs_data_list]
    return (rs_data_list, mac_tag_list)

  def downloader_helper(self, rs_data_list, mac_tag_list, receiver_sk, sender_pk, chunkSize = 262144):
    """
    Parameters:
      rs_data_list
      mac_tag_list
      receiver_sk
      sender_pk
      chunkSize: 262144 (256 KB) # you can also modify it
    Returns:
      recovered_content: bytearray
    """
    #1. generate shared secret between the sender and the receiver
    shared_secret = gen_shared_secret(receiver_sk, sender_pk)
    #2. obtain the encryption key and the mac key
    enc_key, mac_key = gen_aes_mac_key(shared_secret)
    #3. check message integrity
    for i in range(len(rs_data_list)):
      rs_data_chunk = rs_data_list[i]
      mac_tag = mac_tag_list[i]
      verif_flag = ver_mac_tag(rs_data_chunk, mac_tag, mac_key)
      if not verif_flag:
        print("block {} has been tampered", i)
    #4. recover using reedsolomon redundancy method || NOT complete
    enc_data_list = rs_data_list
    #5. decrypt the file chunk using the symmetric encryption key
    data_list = [aes_dec(chunk, enc_key) for chunk in enc_data_list]
    #6. combine the data_list
    recovered_content = combine(data_list)
    return recovered_content

# def test():
#   ##---------------- neo given
#   public_addr_1 = "0xD4cdE7b7480CC3228D3725FB1b8D8d4226267bA3"
#   private_key_1 = "0x7004f17e0cab05642f36e8ddb30b778c4ba5b6d2bc2a17338aaff3b26c55e241"
#   public_key_1 = "0x47d9eab50b1eabd3f493e807ba3ff22f387dcf146430e31f42c98b7ec7fbc9a40eef2080249846ca63521da29f0bcaa2049a0105cbd865d91973059a10d00daa"
#   ##---------------- neo given
#   public_addr_2 =  "0x290FABa2538A49e641e92f330CCA5afc1Ff2076C"
#   private_key_2 =  "0xb6c5753277f0f69e8f66196293772ce624d90a58edbfd9275ec426744ecd2dcf"
#   public_key_2 = "0xa4c6fcffb1411ba3c5335f9971114603d4c58f3b53e149f1a78128de50f475f2a2b22b780c9a94c83e4de662f54fd826a239633a0e3cb0c4537f591a70a386c0"
#   ##---------------- neo given
#   public_addr_3 = "0x58148928Cc24aA0f4025F171cDF958eA24143211"
#   private_key_3 = "0x4a561ed4832e2787355f63010ffa05453bf190b7f50b5aa8d01433a6a4fbe67a"
#   public_key_3 = "0x583f3823024eff1d6c19cd93a4b8fb48a3bd2d8e868ddcc26ffa99553046bbf77eb1fdb85d463b73d639ad395c7c7307d29510c1781032ef450c739d8415b1cc"
#   ##---------------- yoyo generate
#   public_addr_4 ="0x28AbB50DdB82da709E2e47Eef2ECAdAC5e230e83"
#   private_key_4 = "0x3077020101042085af18963da3c5ae8e1b3f5315769048a1dd604968a3605fb9"
#   public_key_4 ="0xaf1e8c0521f5bc7ce85a3b4c2e312cc2458b62db3f0a7660c285abaa77dc09d4d83a34074648e077ad9f1f217ce23921c47e5e0d7920ef6d5087f9a9bdb6fd59"
#
#   ##----------------
#   ##test for varification of ethereum key pair
#   varify_eth_keypair(private_key_4, public_addr_4)
#   ##----------------
#   ##test for shared
#   test_shared_secret(public_key_3[2:], private_key_3[2:], public_key_2[2:], private_key_2[2:])
#   test_shared_secret(public_key_3[2:], private_key_3[2:], public_key_1[2:], private_key_1[2:])
#   ##----------------
#   ##verify that the shared secret is 32 bytes
#   shared_secret_23 = gen_shared_secret(private_key_2[2:],public_key_3[2:])
#   print("the length of the shared secret between the sender 2 and the receiver 3 is", len(shared_secret_23))
#   ##----------------
#   ##verify that the aes key and the mac key is 32 bytes
#   aes_key, mac_key = gen_aes_mac_key(shared_secret_23)
#   print("the length of the aes key should be 32 bytes, in this test:", len(aes_key))
#   print("the length of the mac key should be 32 bytes, in this test:", len(mac_key))
#   ##----------------
#   ##verify that the encryption/decryptin using an symmetric aes key is correct
#   data_chunk = b'This is a sample data chunk that will be encrypted and decrypted using AES in CBC mode with PKCS#7 padding.'
#   test_aes_encryption(data_chunk, aes_key)
#   enc_chunk = aes_enc(data_chunk, aes_key)
#   ##----------------
#   ##verify that the generation and verification of the mac key is consistent
#   test_mac(enc_chunk, mac_key)
#   ##----------------
#   ##reed-solomon redundancy
#
# test()