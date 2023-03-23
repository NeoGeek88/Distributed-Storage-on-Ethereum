"""
Creater : Yoyo Wang
Create Time : March 2023
---------------------------
Main Functionalities:
1. Encryption - Decryption | Public
2. Redundancy - Recover | 
---------------------------
Test: 
1. Check a file is reconstructed after encryption and decryption process
2. Check the a missing chunk can be recovered using the redundancy method
----------------------------
API calls:
Usage: Client to upload file:
       Input - filepath, (chunkSize=256KB=262144B), (redundency M+N),  
       Output - encrypted and redundant chunk List for a file
                + (optional) hash value List of the encrypted redundant chunk List {chunk:hash}
Usage: Client to download file:
       Input - encrypted and redundant chunks which are already verified to be the component of the file, (recovered FilePath)
       Output - recovered file

"""

import io
from PyPDF2 import PdfReader, PdfWriter
#import hashlib
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


class CRSErasureCode:
    def __init__(self, data_size, parity_size, field_size=2**8):
        self.data_size = data_size
        self.parity_size = parity_size
        self.field = ffield.FField(field_size)

        self.encode_matrix = np.zeros((self.parity_size, self.data_size + self.parity_size), dtype=int)
        for i in range(self.parity_size):
            for j in range(self.data_size + self.parity_size):
                self.encode_matrix[i][j] = self.field.Exp(i) ** j

        self.decode_matrix = np.zeros((self.data_size, self.data_size), dtype=int)
        for i in range(self.data_size):
            for j in range(self.data_size):
                self.decode_matrix[i][j] = self.field.Exp(i) ** (self.data_size + j)

        self.decode_matrix_inv = np.linalg.inv(self.decode_matrix)

    def encode(self, data):
        parity = np.dot(self.encode_matrix, data)
        return np.concatenate([data, parity])

    def decode(self, data):
        syndromes = np.dot(self.decode_matrix, data[self.data_size:])
        error_locators = np.array([self.field.Div(-s, data[self.data_size + i]) for i, s in enumerate(syndromes)])
        error_locators[error_locators == self.field.Zero()] = self.field.Exp(self.field.Size() - 1)
        error_locator_poly = np.poly1d(error_locators[::-1])
        error_positions = np.array([i for i in range(len(data)) if data[i] == self.field.Zero()])
        error_count = len(error_positions)
        if error_count > self.parity_size:
            raise ValueError("Too many errors to correct.")
        for i, position in enumerate(error_positions):
            error_evaluator_poly = np.poly1d([1])
            for j in range(len(error_positions)):
                if j != i:
                    error_evaluator_poly *= np.poly1d([1, self.field.Div(-position, error_positions[j])])
            error_value = self.field.Div(np.polyval(error_locator_poly, self.field.Div(-position, self.field.One())), np.polyval(error_evaluator_poly, self.field.One()))
            data[position] = error_value
        return data[:self.data_size]


class FileHandler():

	def __init__(self):
		self.hello = "hello world"
		self.__privateKey = None
		self.publicKey = None
		#self.__generateKeyPair()
		self.crs = CRSErasureCode(data_size=10, parity_size=2)

	def uploadFile(self):
		"""
		Public function to Lawrence
		"""
		pass

	def downloadFile(self):
		"""
		Public function to Lawrence
		"""
		pass

	def __readFile(self, filePath):
		"""
		Private Function 
		Input: filePath
		Output: bytearray of file
		"""
		pass

	def __writeFile(self, bytearray, filePath, fileFormat):
	    """
	    Writes a bytearray to a file in the specified format.

	    Parameters:
	    - bytearray_data (bytearray): The bytearray to write to the file.
	    - filePath (str): The path and filename to write the file to.
	    - fileFormat (str): The format to write the file in. Valid values are 'binary', 'pdf', 'txt', 'csv', 'json', 'png', 'zip'.

	    Returns:
	    - None
	    """
	    if file_format == 'binary':
	    	with open(file_path, 'wb') as f:
	            f.write(bytearray_data)
	    elif file_format == 'pdf':
	        with open(file_path, 'wb') as f:
	            f.write(bytearray_data)
	    elif file_format == 'txt':
	        with open(file_path, 'w') as f:
	            f.write(bytearray_data.decode())
	    elif file_format == 'csv':
	        rows = bytearray_data.decode().split('\n')
	        data = [row.split(',') for row in rows if row]
	        with open(file_path, 'w', newline='') as f:
	            writer = csv.writer(f)
	            writer.writerows(data)
	    elif file_format == 'json':
	        data_dict = {'data': list(bytearray_data)}
	        with open(file_path, 'w') as f:
	            json.dump(data_dict, f)
	    elif file_format == 'png':
	        img = Image.open(BytesIO(bytearray_data))
	        img.save(file_path, format='PNG')
	    elif file_format == 'zip':
	        zip_data = BytesIO()
	        with zipfile.ZipFile(zip_data, mode='w') as zf:
	            zf.writestr('data.bin', bytearray_data)
	        with open(file_path, 'wb') as f:
	            f.write(zip_data.getvalue())
	    else:
	        raise ValueError(f"Invalid file format: {file_format}")

	def __split(self, fileBytearray, chunkSize):
		"""
		Private Function
		
		Returns: 
		Chunks (List[bytearray]), each chunk has length = chunksize
		"""
		pass

	def __combine(self, chunkList):
		pass

        def __generateKeyPair(self, public_exponent=65537, key_size=2048):
            pass
            #self.__privateKey = 111
            #self.publickey = 222

        def __encChunk(self, chunkBytearray):
            """
            Private

            Parameters:
                    chunkByteArray (bytearray)

            Returns: 
                    encrypted Chunk
            """
            pass

        def __decChunk(self, encChunk):
            """
            Private

            Parameters:
                    encChunk (bytearray)

            Returns:
                    chunkByteArray (bytearray)
            """
            pass

        def __RSenc(self, encChunkList):
            rsencChunkList = [self.crs.encode(echunk) for echunk in encChunkList]

        def __RSdec(self, rsencChunkList):
            encChunkList = [self.crs.decode(rehunk) for rechunk in rsencChunkList]

        def __hash(self, rechunk):
            hash_object = hashlib.sha256()
            hash_object.update(rechunk)
            hash_hex = hash_object.hexdigest()
            return hash_hex





