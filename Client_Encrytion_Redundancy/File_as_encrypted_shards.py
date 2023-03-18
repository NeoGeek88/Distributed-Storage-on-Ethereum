"""
STEP1. Convert the file into byte array format and split into shards with a given size. 
       If there exists extra space in the last shard, fill it with zero bytes.
    1.1. convert a file into bytecode
    1.2. split the file into some standard byte-multiple like 32 MB. 
         any extra space is zero filled
         The unit is MB
STEP2. Encrypt the byte form of the shard using a secure encryption algorithm such as AES. 
       Generate key pairs for asymmetric encryption, using public key to encrypt and private key to decrypt.
    2.1. Devide the shard into even smaller piece
STEP3. Apply Reed-Solomon erasure coding to the encrypted data to create redundancy shards.
--------------------------------------------------------------------------------------------------
Test:
     1. Check whether the bincode can be recovered to the original file 
     2. Check after combing the shards (including the padding shard) the binary byte code can be recovered to original file
"""


import io
from PyPDF2 import PdfReader, PdfWriter
#import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


def split_file2shard(file_bin, shard_size):
	print('The size of the binary code is {} MB'.format(len(file_bin)/(1024*1024) ))
	bin_shards = [ bytearray(file_bin[i:i+shard_size])for i in range(0, len(file_bin), shard_size)]
	if bin_shards:
		remain_bytes = shard_size-len(bin_shards[-1])
		bin_shards[-1].extend(bytearray(remain_bytes))
	return bin_shards

class fileUpload():

	def __init__(self):
		self.filename = 'storj2014.pdf'
		self.shard_size = 0.25
		self.generate_keypair()
		self.enc_shard_size =  0.0001

	def convert2bin(self):
		with open(self.filename, 'rb') as file:
			pdf_bytes = file.read()
			bin_code = bytearray(pdf_bytes)
		return bin_code

	def split2shard(self):
		return split_file2shard(file_bin = self.convert2bin(), shard_size = int(self.shard_size*1024*1024))

	def writebin2file(self, bincode):
		output = PdfWriter()
		page = output.add_blank_page(width=72, height=72)
		page.merge_page(PdfReader(io.BytesIO(bincode)).Pages[0])
		# write the PDF document to a file
		with open('output.pdf', 'wb') as f:
			output.write(f)
		print('done')

	# generate a private/public key pair
	def generate_keypair(self):
   	# Generate the private key
		self.private_key = rsa.generate_private_key( public_exponent=65537, key_size=2048, backend=default_backend())
		# Generate the corresponding public key
		self.public_key = self.private_key.public_key()
		
		# pem_private_key = private_key.private_bytes(encoding = serialization.Encoding.PEM, format = serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
		# pem_public_key = public_key.public_bytes( encoding = serialization.Encoding.PEM,format = serialization.PublicFormat.SubjectPublicKeyInfo)
		# print("Private key:")
		# print(pem_private_key.decode('utf-8'))
		# print("Public key:")
		# print(pem_public_key.decode('utf-8'))

	def enc_shard(self,bin_shard):
		bin_chunks = split_file2shard(bin_shard, int(self.enc_shard_size*1024*1024))
		encrypted_chunks = []
		for bin_chunk in bin_chunks:
			encrypted_chunk = self.public_key.encrypt(
			   bytes(bin_chunk),
			   padding.OAEP(
			        mgf=padding.MGF1(algorithm=hashes.SHA256()),
			        algorithm=hashes.SHA256(),
			        label=None
			   )
			)
			encrypted_chunks.append(bytearray(encrypted_chunk))
		return encrypted_chunks

	def dec_shard(self, enc_shard):
		# Decrypt the message using the private key
		decrypted_chunks = bytearray()
		for enc_chunk in enc_shard:
			decrypted_chunk = self.private_key.decrypt(
			   bytes(enc_chunk),
				padding.OAEP(
				   mgf=padding.MGF1(algorithm=hashes.SHA256()),
				   algorithm=hashes.SHA256(),
				   label=None
				)
			)
		decrypted_chunks.extend(bytearray(decrypted_chunk))
		return decrypted_chunks


	def hash_shard(self,bin_shard):
		hash_object = hashlib.sha256()
		hash_object.update(bin_shard)
		hash_hex = hash_object.hexdigest()
		return hash_hex



if __name__ == "__main__":
   ## initiate the fileUpload object
	fileUpload = fileUpload()
	
	## Test whether the bin-code can be convert to the original file
	#bin_code = fileUpload.convert2bin()
	#fileUpload.writebin2file(recover_bin_code)
	
	## Check after combing the shards (including the padding shard) the binary byte code can be recovered to original file
	# bin_shards = fileUpload.split2shard()
	# recover_bin_code = bytearray()
	# for item in bin_shards:
	# 	recover_bin_code.extend(bytearray(item))
	# fileUpload.writebin2file(recover_bin_code)

	bin_shards = fileUpload.split2shard()
	print(bin_shards[0][:100])
	#bin_shards = [bytearray(b"hello world")]
	enc_chunks_list = []
	for bin_shard in bin_shards:
		enc_chunks = fileUpload.enc_shard(bin_shard)
		enc_chunks_list.append(enc_chunks)
	
	dec_code = bytearray()
	for enc_chunks in enc_chunks_list:
		dec_shard = fileUpload.dec_shard(enc_chunks)
		dec_code.extend(dec_shard)
	print(dec_code[:100])
	fileUpload.writebin2file(bytearray(b'hello world'))


