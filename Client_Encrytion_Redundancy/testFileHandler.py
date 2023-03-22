import os
import tempfile
import unittest
from file_handler import FileHandler


class TestFileHandler(unittest.TestCase):
    
    def setUp(self):
        self.file_handler = FileHandler()

    
    def testRW(self, filePath, writePath, fileFormat):
        file_content= self.file_handler.readFile(filePath)
        self.file_handler.writeFile(file_content, writePath, fileFormat)
        file_content2 = self.file_handler.readFile(writePath)
        self.assertEqual(file_content, file_content2)


    def testED(self): 
        # check publicKey number
        publicKey_num = self.file_handler.publicKey.public_numbers()
        print(publicKey_num)

        # create sample encrypted chunks
        chunk_1 = bytearray(b'encrypted chunk 1')
        chunk_2 = bytearray(b'stupid homework')
        chunk_3 = bytearray(b'happy everyday')
        chunk_list = [chunk_1, chunk_2, chunk_3]

        # check encryption-decryption method is correct or not
        for chunk in chunk_list:
            enc_chunk = self.file_handler.encChunk(chunk)
            dec_enc_chunk = self.file_handler.decChunk(enc_chunk)
            self.assertEqual(chunk, dec_enc_chunk)

    def testSC(self):
        pass

    def testUD(self):
        pass

    def testRSenc(self):
        # create sample encrypted chunks
        enc_chunk_1 = bytearray(b'encrypted chunk 1')
        enc_chunk_2 = bytearray(b'encrypted chunk 2')
        enc_chunk_3 = bytearray(b'encrypted chunk 3')

        # create list of encrypted chunks
        enc_chunk_list = [enc_chunk_1, enc_chunk_2, enc_chunk_3]

        # encode chunks using RS
        rs_enc_chunk_list = self.file_handler.RSenc(enc_chunk_list)

        # ensure that encoded list is not empty
        self.assertIsNotNone(rs_enc_chunk_list)

        # ensure that length of encoded list is correct
        self.assertEqual(len(rs_enc_chunk_list), len(enc_chunk_list) + self.file_handler.crs.parity_size)

        # decode chunks using RS
        dec_chunk_list = self.file_handler.RSdec(rs_enc_chunk_list)

        # ensure that decoded list is not empty
        self.assertIsNotNone(dec_chunk_list)

        # ensure that length of decoded list is correct
        self.assertEqual(len(dec_chunk_list), len(enc_chunk_list))

        # ensure that decoded chunks are equal to original encrypted chunks
        for i in range(len(enc_chunk_list)):
            self.assertEqual(dec_chunk_list[i], enc_chunk_list[i])



if __name__ == "__main__":
    testFile = TestFileHandler()
    testFile.setUp()
    testFile.testED()

    filePath = "testFiles/storj2014.pdf"
    testFile.testRW(filePath,'testFiles/testCopyPdf.pdf','pdf')

    filePath2 = "testFiles/testZip.zip"
    testFile.testRW(filePath2,'testFiles/testCopyZip.zip','zip')

    #filePath3 = "testFiles/testTxt.txt"
    #testFile.testRW(filePath3,'testFiles/testCopyTxt.txt','txt')

    filePath4 = "testFiles/testPng.png"
    testFile.testRW(filePath4,'testFiles/testCopyPng.png','png')


