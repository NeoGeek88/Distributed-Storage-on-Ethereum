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
from PyPDF2 import PdfFileReader
import imghdr


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
        self.__generateKeyPair()
        #self.crs = CRSErasureCode(data_size=10, parity_size=2)

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
        Private Function
        
        Returns: 
        Chunks (List[bytearray]), each chunk has length = chunksize
        """
        pass

    def combine(self, chunkList):
        pass

    def __generateKeyPair(self, public_exponent=65537, key_size=2048):
        # Generate the private key
        self.__privateKey = rsa.generate_private_key( public_exponent, key_size, backend=default_backend())
        # Generate the corresponding public key
        self.publicKey = self.__privateKey.public_key()

    def encChunk(self, chunkBytearray):
        """
        Private

        Parameters:
                chunkByteArray (bytearray)

        Returns: 
                encrypted Chunk
        """
        echunk = self.publicKey.encrypt(
            bytes(chunkBytearray),
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
                )
            )
        return echunk

    def decChunk(self, encChunk):
        """
        Private

        Parameters:
                encChunk (bytearray)

        Returns:
                chunkByteArray (bytearray)
        """
        dchunk = self.__privateKey.decrypt(
            bytes(encChunk),
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
                )
            )
        return dchunk

    def RSenc(self, encChunkList):
        rsencChunkList = [self.crs.encode(echunk) for echunk in encChunkList]

    def RSdec(self, rsencChunkList):
        encChunkList = [self.crs.decode(rehunk) for rechunk in rsencChunkList]

    def __hash(self, rechunk):
        hash_object = hashlib.sha256()
        hash_object.update(rechunk)
        hash_hex = hash_object.hexdigest()
        return hash_hex
