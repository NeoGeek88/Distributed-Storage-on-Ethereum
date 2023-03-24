
"""
Creater : Yoyo Wang
Create Time : March 2023
---------------------------
Main Functionalities:
1. Encryption - Decryption | Public
    - Problem: If I only use public encryption method to encrypt a large chunk (256KB), it will return error
    - Solution: Hybraid Encryption. AES encrypt the data chunk with a random key, and using public encryption/decryption to protect the key
2. Redundancy - Recover | 
----------------------------
API calls:
Usage: Client to upload file:
       Input - filepath, (chunkSize=256KB=262144B), (redundency M+N),  
       Output - encrypted and redundant chunk List for a file + encrypted AES key
                + (optional) hash value List of the encrypted redundant chunk List {chunk:hash}
Usage: Client to download file:
       Input - encrypted and redundant chunks which are already verified to be the component of the file, + encrypted AES key + (recovered FilePath)
       Output - recovered file
"""


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
#from PIL import Image
import zipfile
from pyfinite import ffield
import numpy as np
from PyPDF2 import PdfFileReader
import imghdr
from reedsolo import RSCodec
import numpy as np


class FileHandler():

    def __init__(self):
        self.hello = "hello world"
        self.privateKey = None
        self.publicKey = None
        self.chunkSize = 262144
        self.__generateKeyPair()
        #self.crs = CRSErasureCode(data_size=262144, parity_size=2)
        self.ecc_symbols = 2  # Number of error correction symbols
        self.rs = RSCodec(self.ecc_symbols)

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
        4. assymetric encrypt(AES-key)
        5. AES encrypt(chunk) using AES key
        6. redundancy -> RS encode
        """ 
        file_content = self.readFile(local_file_path)
        chunk_list = self.split(file_content, self.chunkSize)
        AES_key = self.generate_AES_key()
        enc_AES_key = self.enc_AES_key(self.publicKey, AES_key)
        enc_chunk_list = [self.AES_enc(chunk, AES_key) for chunk in chunk_list]
        rs_chunk_list = self.RSenc(enc_chunk_list)
        return rs_chunk_list, enc_AES_key


    def downloadFile(self, rs_chunk_list, enc_AES_key, writePath):
        """
        Public function to Lawrence
        Input (maybe destroyed | but must verified) rs_chunk_list
        -------------------------------------------
        Steps only for me:
        1. rs decode -> dec_chunk_list
        2. decrypt enc_AES_key to obtain AES key, using private key
        3. decrypt dec_chunk_list using AES key to obtain chunk_list
        4. combine
        5. write to local file
        """
        enc_chunk_list = self.RSdec(rs_chunk_list)
        enc_chunk_list = [bytes(chunk[0]) for chunk in enc_chunk_list]
        AES_key = self.dec_AES_key(self.privateKey, enc_AES_key)
        chunk_list = [self.AES_dec(enc_chunk, AES_key) for enc_chunk in enc_chunk_list]
        recovered_content = self.combine(chunk_list)
        self.writeFile(recovered_content, writePath, 'pdf')

        

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

    def writeFile(self, bytearray_data, file_path, file_format):
        """
        Writes a bytearray to a file in the specified format.

        Parameters:
        - bytearray_data (bytearray): The bytearray to write to the file.
        - file_path (str): The path and filename to write the file to.
        - file_format (str): The format to write the file in. Valid values are 'binary', 'pdf', 'txt', 'csv', 'json', 'png', 'zip'.

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
            with open(file_path, 'wb') as f:
                f.write(bytearray_data.decode().replace('\r\n', '\n').encode())
        elif file_format == 'csv':
            with open(file_path, 'wb') as f:
                writer = csv.writer(f)
                rows = bytearray_data.decode().split('\n')
                for row in rows:
                    if row:
                        writer.writerow(row.split(','))
        elif file_format == 'json':
            with open(file_path, 'w') as f:
                f.write(json.dumps({'data': list(bytearray_data)}))
        elif file_format == 'png':
            img = Image.open(BytesIO(bytearray_data))
            img.save(file_path, format='png')
        elif file_format == 'zip':
            zip_data = BytesIO()
            with zipfile.ZipFile(zip_data, mode='w') as zf:
                zf.writestr('data.bin', bytearray_data)
            with open(file_path, 'wb') as f:
                f.write(zip_data.getvalue())
        else:
            raise ValueError(f"Invalid file format: {file_format}")

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

    def generate_AES_key(self):
        """
        Generate a random symmetric 32bytes(256Bits) key for AES encryption
        CBC-AES: 128bits for encryption + 128bits for IV 
        """
        key = secrets.token_bytes(32)
        key = base64.urlsafe_b64encode(key)
        return key

    def __generateKeyPair(self, public_exponent=65537, key_size=2048):
        """
        Generate Public Encryption Key pair
        """
        # Generate the private key
        self.privateKey = rsa.generate_private_key( public_exponent, key_size, backend=default_backend())
        # Generate the corresponding public key
        self.publicKey = self.privateKey.public_key()

    def enc_AES_key(self, publicKey,AES_key):
        """
        Public encryption for a 32 bytes AES key 
        """
        # ekey = self.publicKey.encrypt(
        #     bytes(AES_key),
        #     padding.OAEP(
        #         mgf = padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm = hashes.SHA256(),
        #         label = None
        #         )
        #     )
        # return ekey
        ekey = publicKey.encrypt(
            bytes(AES_key),
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
                )
            )
        return ekey

    def dec_AES_key(self, privateKey, enc_AES_key):
        """
        Public decryption for a 32 bytes AES key
        """
        # dkey = self.__privateKey.decrypt(
        #     bytes(enc_AES_key),
        #     padding.OAEP(
        #         mgf = padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm = hashes.SHA256(),
        #         label = None
        #         )
        #     )
        # return dkey
        dkey = privateKey.decrypt(
            bytes(enc_AES_key),
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
                )
            )
        return dkey

    def AES_enc(self, chunk, AES_key):
        enc_helper = Fernet(AES_key)
        enc_chunk = enc_helper.encrypt(bytes(chunk))
        return enc_chunk

    def AES_dec(self, enc_chunk, AES_key):
        dec_helper = Fernet(AES_key)
        dec_enc_chunk = dec_helper.decrypt(enc_chunk)
        return dec_enc_chunk
    
    def RSenc(self, encChunkList):
        encoded_data = []
        for chunk in encChunkList:
            encoded_chunk = self.rs.encode(chunk)
            encoded_data.append(encoded_chunk)
        return encoded_data

    def RSdec(self, rsencChunkList):
        decoded_data = []
        for encoded_chunk in rsencChunkList:
            try:
                decoded_chunk = self.rs.decode(encoded_chunk)
                decoded_data.append(decoded_chunk)
            except reedsolo.ReedSolomonError:
                print("Unable to decode chunk")
        return decoded_data

    def __hash(self, rechunk):
        hash_object = hashlib.sha256()
        hash_object.update(rechunk)
        hash_hex = hash_object.hexdigest()
        return hash_hex
