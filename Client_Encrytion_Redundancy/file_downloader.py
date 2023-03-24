"""
Creater : Yoyo Wang
Create Time : March 22 2023
Last Modify Time : March 22 2023
--------------------------------------------------------------
File Owner | Authorized User | File uploader | File downloader
--------------------------------------------------------------
Main Functionality:
File Downloader (Authorized Users or File Owner):
	1. Download the encrypted file and the corresponding encrypted symmetric key.
	2. Decrypt the symmetric key using their private key.
	3. Decrypt the file using the decrypted symmetric key.
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
from PIL import Image
import zipfile
from pyfinite import ffield
import numpy as np
from PyPDF2 import PdfFileReader
import imghdr
from reedsolo import RSCodec
import numpy as np

from users import user

class fileDownloader(user):

	def __init__(self):
		self.privateKey = user.privateKey
		self.userId = user.Id

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

    def dec_AES_key(self, privateKey, enc_AES_key):
        """
        Public decryption for a 32 bytes AES key
        """
        dkey = privateKey.decrypt(
            bytes(enc_AES_key),
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
                )
            )
        return dkey

    def AES_dec(self, enc_chunk, AES_key):
        dec_helper = Fernet(AES_key)
        dec_enc_chunk = dec_helper.decrypt(enc_chunk)
        return dec_enc_chunk

    def RSdec(self, rsencChunkList):
        decoded_data = []
        for encoded_chunk in rsencChunkList:
            try:
                decoded_chunk = self.rs.decode(encoded_chunk)
                decoded_data.append(decoded_chunk)
            except reedsolo.ReedSolomonError:
                print("Unable to decode chunk")
        return decoded_data

    def downloadFile(self, rs_chunk_list, dict_enc_keys, writePath):
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
        -------------------------------------------
        """
        enc_chunk_list = self.RSdec(rs_chunk_list)
        enc_chunk_list = [bytes(chunk[0]) for chunk in enc_chunk_list]
        enc_AES_key = dict_enc_keys[self.userId]
        AES_key = self.dec_AES_key(self.privateKey, enc_AES_key)
        chunk_list = [self.AES_dec(enc_chunk, AES_key) for enc_chunk in enc_chunk_list]
        recovered_content = self.combine(chunk_list)
        self.writeFile(recovered_content, writePath, 'pdf')