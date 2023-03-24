
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


class user():
	
    def __init__(self):
        self.Id = None
		self.privateKey = None
		self.publicKey = None
        self.__generateKeyPair()
        self.accessUsers = []

	def __generateKeyPair(self, public_exponent=65537, key_size=2048):
        """
        Generate Public Encryption Key pair
        """
        # Generate the private key
        self.privateKey = rsa.generate_private_key( public_exponent, key_size, backend=default_backend())
        # Generate the corresponding public key
        self.publicKey = self.privateKey.public_key()


class fileOwner():

    def __init__(self):

    def __generateKeyPair(self, public_exponent=65537, key_size=2048):
        """
        Generate Public Encryption Key pair
        """
        # Generate the private key
        self.privateKey = rsa.generate_private_key( public_exponent, key_size, backend=default_backend())
        # Generate the corresponding public key
        self.publicKey = self.privateKey.public_key()

class authorizedUsers():

    def __init__(self):
        pass




