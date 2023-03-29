import os
import tempfile
import unittest
from cryptography.fernet import Fernet
from file_handler import FileHandler
import random
import json


class TestFileHandler(unittest.TestCase):
    
    def setUp(self):
        self.file_handler = FileHandler()
    
    def testRW(self, filePath, writePath, fileFormat):
        file_content= self.file_handler.readFile(filePath)
        self.file_handler.writeFile(file_content, writePath, fileFormat)
        file_content2 = self.file_handler.readFile(writePath)
        self.assertEqual(file_content, file_content2)

    def testSC(self):
        """
        TEST the split + combine function
        """
        file_content= self.file_handler.readFile("testFiles/storj2014.pdf")        
        chunk_list = self.file_handler.split(file_content, chunkSize = 262144 )
        for chunk in chunk_list:
            self.assertEqual(len(chunk),262144)
        combined_chunk = self.file_handler.combine(chunk_list)
        self.assertEqual(file_content,combined_chunk)
        print("Splitting Function and combine function implemented correctly !")

    def testSC_RW(self, filePath, writePath, fileFormat):
        file_content= self.file_handler.readFile(filePath)
        chunk_list = self.file_handler.split(file_content, chunkSize = 262144 )
        combined = self.file_handler.combine(chunk_list)
        self.file_handler.writeFile(combined, writePath, fileFormat)
        recover_content = self.file_handler.readFile(writePath)
        self.assertEqual(file_content, recover_content)
        print("Splitting/Combination function implemented correctly under the read/write check!")

    def test_key_ED(self): 
        """
        TEST the assymetric RSA encryption/decryption, note this is used to encrypt/decrypt 32 bytes AES key 
        """
        for i in range(10):
            key = self.file_handler.generate_AES_key()
            #self.assertEqual(len(key),32)
            enc_key = self.file_handler.enc_AES_key(self.file_handler.publicKey, key)
            dec_enc_key = self.file_handler.dec_AES_key(self.file_handler.privateKey, enc_key)
            self.assertEqual(key, dec_enc_key)
        print("Assymetric Encryption is implemented correctly !")

    def test_AES_ED(self): 
        """
        TEST the symmetric RSA encryption, which use the secret AES key to encrypt/decrypt a chunk of size 256 KB
        """
        file_content= self.file_handler.readFile("testFiles/storj2014.pdf")        
        chunk_list = self.file_handler.split(file_content, chunkSize = 262144)
        sample_chunk = chunk_list[random.randint(0,len(chunk_list)-1)]
        AES_key = self.file_handler.generate_AES_key()
        enc_chunk = self.file_handler.AES_enc(sample_chunk, AES_key)
        dec_enc_chunk = self.file_handler.AES_dec(enc_chunk, AES_key)
        self.assertEqual(sample_chunk, dec_enc_chunk)
        print("AES encryption/decryption implemented correctly under the spliting/combination check, given an AES key!")

        file_content= self.file_handler.readFile("testFiles/storj2014.pdf")        
        chunk_list = self.file_handler.split(file_content, chunkSize = 262144)
        sample_chunk = chunk_list[random.randint(0,len(chunk_list)-1)]
        secret_AES_key = self.file_handler.generate_AES_key() ## this is a secrete, we cannot give to the AES_enc function right now
        enc_AES_key = self.file_handler.enc_AES_key(self.file_handler.publicKey, secret_AES_key) ## Now this secrete is encrypted using public key, and we can give it to the encryption function
        dec_enc_AES_key = self.file_handler.dec_AES_key(self.file_handler.privateKey,enc_AES_key)
        self.assertEqual(secret_AES_key, dec_enc_AES_key)
        enc_chunk = self.file_handler.AES_enc(sample_chunk, AES_key)
        dec_enc_chunk = self.file_handler.AES_dec(enc_chunk, AES_key)
        self.assertEqual(sample_chunk, dec_enc_chunk)
        print("AES encryption/decryption implemented correctly under the spliting/combination check, Also AES key is successfully protected through Assymetric encryption!")

    def introduce_errors(self, encoded_chunks, error_prob=0.01, drop_prob=0.1):
        corrupted_chunks = []
        for chunk in encoded_chunks:
            # Drop the chunk with a specified probability
            if random.random() < drop_prob:
                print("drop")
            # Introduce errors in the chunk with a specified probability
            corrupted_chunk = bytearray(chunk)
            for i in range(len(corrupted_chunk)):
                if random.random() < error_prob:
                    corrupted_chunk[i] = random.randint(0, 255)
            corrupted_chunks.append(bytes(corrupted_chunk))
        return corrupted_chunks

    def testRSed(self):
        for drop_prob in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]:
            pass_num = 0
            for num_errors in range(1,30):
                chunks = [b'hello', b'world', b'python', b'rocks', b'life', b'hard']
                encoded_chunks = self.file_handler.RSenc(chunks)
                corrupted_chunks = self.introduce_errors(encoded_chunks, drop_prob = drop_prob)
                recovered_chunks_all = self.file_handler.RSdec(corrupted_chunks)
                recovered_chunks = [bytes(chunk[0]) for chunk in recovered_chunks_all]
                self.assertEqual(chunks,recovered_chunks)
                pass_num += 1
            print("Test passed count", pass_num, drop_prob)


    def testRSed_File(self):
        #filePath = "testFiles/storj2014.pdf" ## 500KB
        filePath = "testFiles/group.pdf" ## 1.9MB
        rs_chunk_list, enc_AES_key = self.file_handler.uploadFile(filePath)
        corrupted_chunks = self.introduce_errors(rs_chunk_list, drop_prob = 0.1)
        self.file_handler.downloadFile(corrupted_chunks, enc_AES_key, "testFiles/test.pdf")


    def testUD(self, read_file_path, write_file_path):
        file_content = self.file_handler.readFile(read_file_path)
        [rs_chunk_list, enc_AES_key]= self.file_handler.uploadFile(read_file_path)
        print('1')
        self.file_handler.downloadFile(rs_chunk_list, enc_AES_key,write_file_path)
        recover_content = self.file_handler.readFile(write_file_path)
        self.assertEqual(file_content, recover_content)
        print("Test Passed: you can successfully upload a file to the cloud and download it from the cloud")

    def test888(self, filePath, filePath2, writePath): 
        with open(filePath, 'rb') as file:
        # Load the JSON data from the file
            data = json.load(file)
        chunk_list = [bytearray(chunkinfo["chunk"],'utf-8') for chunkinfo in data["file_chunks"]  ]
        with open(filePath2, 'rb') as file2:
            data = json.load(file2)
        aes_key = bytearray(data["storj2014.pdf"], 'utf-8')
        self.file_handler.downloadFile(chunk_list, aes_key, writePath)



if __name__ == "__main__":
    testFile = TestFileHandler()
    testFile.setUp()
    #testFile.test_key_ED()
    #testFile.testSC()
    #testFile.testSC_RW("testFiles/storj2014.pdf", 'testFiles/testCopyPdf.pdf', 'pdf')
    #testFile.test_AES_ED()
    #testFile.testRSed()
    #testFile.testRSed_File()
    #testFile.testUD("testFiles/storj2014.pdf", 'testFiles/testCopyPdf.pdf')
    testFile.test888("testFiles/uploaded_file.json", "testFiles/aes_key.json", 'testFiles/test888.pdf')

    #filePath = "testFiles/storj2014.pdf"
    #testFile.testRW(filePath,'testFiles/testCopyPdf.pdf','pdf')



    # filePath2 = "testFiles/testZip.zip"
    # testFile.testRW(filePath2,'testFiles/testCopyZip.zip','zip')

    #filePath3 = "testFiles/testTxt.txt"
    #testFile.testRW(filePath3,'testFiles/testCopyTxt.txt','txt')

    # filePath4 = "testFiles/testPng.png"
    # testFile.testRW(filePath4,'testFiles/testCopyPng.png','png')


