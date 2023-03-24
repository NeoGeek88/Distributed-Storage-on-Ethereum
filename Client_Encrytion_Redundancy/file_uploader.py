"""
Creater : Yoyo Wang
Create Time : March 22 2023
Last Modify Time : March 22 2023
--------------------------------------------------------------
File Owner | Authorized User | File uploader | File downloader
--------------------------------------------------------------
Main Functionality:
File Uploader (Only File Owner):
	Generate a symmetric key (e.g., an AES key).
	Encrypt the file using the symmetric key.
	Encrypt the symmetric key with the public key of the file owner and each authorized user.
	Upload the encrypted file along with the encrypted symmetric keys.
"""

from users import user

import io
from PyPDF2 import PdfReader, PdfWriter
#import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import csv
import json
from io import BytesIO
from PIL import Image
import zipfile
from pyfinite import ffield
import numpy as np
from PyPDF2 import PdfFileReader
import imghdr
from reedsolo import RSCodec
import numpy as np

from users import user


class fileUploader(user):

	def __init__(self):
		self.accessUsers = user.accessUsers
        
    def readFile(self, filePath):
        """
        Reads the contents of a file in the specified format.

        Parameters:
        - filePath (str): The path and filename to read the file from.

        Returns:
        - The contents of the file as a bytearray.
        """
        with open(filePath, 'rb') as f:
            file_bytes = f.read()

        if filePath.endswith('.txt') or filePath.endswith('.csv') or filePath.endswith('.json'):
            return file_bytes.decode().encode()
        elif filePath.endswith('.pdf'):
            # Read PDF as binary data
            return file_bytes
        elif filePath.endswith('.png'):
            # Read PNG as binary data
            return file_bytes
        elif filePath.endswith('.zip'):
            # Read ZIP archive
            with zipfile.ZipFile(BytesIO(file_bytes)) as zf:
                # Assume only one file in ZIP archive
                filename = zf.namelist()[0]
                with zf.open(filename) as f:
                    return f.read()
        else:
            raise ValueError("Invalid file format")

    def split(self, fileBytearray, chunkSize):
        """
        Padding
        Chunks (List[bytearray]), each chunk has length = chunksize
        """
        chunk_list = [ bytearray(fileBytearray[i:i+chunkSize])for i in range(0, len(fileBytearray), chunkSize)]
        if chunk_list:
            remain_bytes = chunkSize-len(chunk_list[-1])
            chunk_list[-1].extend(bytearray(remain_bytes))
        return chunk_list

    def generate_AES_key(self):
        """ 
        Generate a random symmetric 32bytes(256Bits) key for AES encryption
        CBC-AES: 128bits for encryption + 128bits for IV 
        """
        key = secrets.token_bytes(32)
        key = base64.urlsafe_b64encode(key)
        return key

    def AES_enc(self, chunk, AES_key):
    	"""
    	Encrypt chunk file using AES key
    	"""
        enc_helper = Fernet(AES_key)
        enc_chunk = enc_helper.encrypt(bytes(chunk))
        return enc_chunk

    def RSenc(self, encChunkList):
        encoded_data = []
        for chunk in encChunkList:
            encoded_chunk = self.rs.encode(chunk)
            encoded_data.append(encoded_chunk)
        return encoded_data

    def enc_AES_key(self, publicKey,AES_key):
        """
        Public encryption for a 32 bytes AES key 
        """
        ekey = publicKey.encrypt(
            bytes(AES_key),
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
                )
            )
        return ekey
    
    def broad_enc_key(self, AES_key):
    	dict_enc_keys = {}
    	for user in self.accessUsers:
    		dict_enc_keys[user] = self.enc_AES_key(self, user.publicKey, AES_key)
    	return dict_enc_keys

    def uploadFile(self, local_file_path):
        """
        Public function to Lawrence
        Return encoded_chunks, encrypted AES key
        ( I can also give you hash values list, what do you want ?)
        ---------------------------------
        Steps only for me:
        1. read local file
        2. split
        3. AES key generate
        4. AES encrypt(chunk) using AES key
        5. redundancy -> RS encode
        6. broad encrypted AES key, encrypted using their public key
        """ 
        file_content = self.readFile(local_file_path)
        chunk_list = self.split(file_content, self.chunkSize)
        AES_key = self.generate_AES_key()
        enc_chunk_list = [self.AES_enc(chunk, AES_key) for chunk in chunk_list]
        rs_chunk_list = self.RSenc(enc_chunk_list)
        dict_enc_keys = self.broad_enc_key(AES_key)
        return rs_chunk_list, dict_enc_keys

