from eth_keys import keys
from eth_utils import keccak, encode_hex, decode_hex
from eth_utils import to_checksum_address
from reedsolo import RSCodec, ReedSolomonError
from Crypto.PublicKey import ECC
from py_ecc import optimized_bls12_381 as b
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.ellipticcurve import Point
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hmac


class FileHandler:
    
    def __init__(self, eth_address, private_key, chunk_size = 262144, redundancy = 2, shared_public_key = None) -> None:
        self.eth_address = eth_address
        self.public_key = self.gen_eth_public_key(private_key)
        self.private_key = private_key
        if not self.verify_eth_keypair(self.private_key, self.gen_eth_public_address(self.public_key)):
            raise Exception("Invalid Ethereum Address<->Private Key pair!")
        if shared_public_key != None:
            self.shared_public_key = shared_public_key
        else:
            self.shared_public_key = None
        if chunk_size % 16 != 0:
            raise Exception("The chunk size must be multiple of 16!")
        self.chunk_size = chunk_size
        self.redundancy = redundancy


    def gen_eth_public_key(self, private_key):
        """
        This function is to generate ethereum public key given a private key
        """
        private_key = keys.PrivateKey(bytes.fromhex(private_key[2:]))
        public_key = private_key.public_key
        return public_key


    def gen_eth_public_address(self, public_key):
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


    def verify_eth_keypair(self, given_private_key, given_public_addr):
        """
        This function is used to verify whether the 
        (public address, private key) is a valid pair in ethereum.
        """
        public_key = self.gen_eth_public_key(given_private_key)
        public_addr = self.gen_eth_public_address(public_key)
        return public_addr == given_public_addr
    

    def gen_shared_secret(self, sender_sk_hex, receiver_pk_hex):
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


    def test_shared_secret(self, sender_pk, sender_sk, receiver_pk, receiver_sk):
       print(self.gen_shared_secret(sender_sk, receiver_pk) == self.gen_shared_secret(receiver_sk, sender_pk))


    def gen_aes_mac_key(self, shared_secret):
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
    

    def aes_enc(self, chunk, aes_key):
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
        # Neo Comment: since we already make every trunk with fixed size (which is always multiple of 16), we did not need to add padding here.
        #padded_chunk = chunk + (16 - len(chunk) % 16) * chr(16 - len(chunk) % 16).encode()
        enc_chunk = encryptor.update(chunk) + encryptor.finalize()
        print(len(enc_chunk))
        return enc_chunk  # return the encrypted data only


    def aes_dec(self, enc_chunk, aes_key):
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
        # Neo Comment: This is to remove the PKCS#7 padding, but it will bug if padding is 16 (\x00).
        # Neo Comment: Since we removed padding for the encoding, so I removed this as well.
        #plaintext = padded_plaintext[:-padded_plaintext[-1]]
        return padded_plaintext


    def test_aes_encryption(self, chunk, aes_key):
        enc_chunk = self.aes_enc(chunk, aes_key)
        dec_chunk = self.aes_dec(enc_chunk, aes_key)
        print(dec_chunk == chunk)


    def gen_mac_tag(self, message, mac_key):
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

    def ver_mac_tag(self, message, mac_tag, mac_key):
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
        new_mac_tag = self.gen_mac_tag(message, mac_key)
        return hmac.compare_digest(mac_tag, new_mac_tag)

    def test_mac(self, enc_chunk, mac_key):
        old_mac_tag = self.gen_mac_tag(enc_chunk, mac_key)
        print(self.ver_mac_tag(enc_chunk, old_mac_tag, mac_key))


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
    

    def split_data(self, data, block_size):
        """Split data into fixed-size blocks"""
        return [data[i:i+block_size] for i in range(0, len(data), block_size)]


    def rs_enc(self, data_chunks):
        """
        This function is to perform Reed Solomon encoding
        WARNING: Since this is a pure-python implementation, the encoding is very much time-consuming
        Average encoding speed for a 256KB trunk = 15 seconds.
        The speed can be optimized if using C library with more than 10x boost.
        Method:
            Reed Solomon
        Parameters:
            data_chunks
        Returns:
            encoded_data_chunks
        """
        # 255 - n = 2k, k = max error byte
        # redundancy = 2 -> k = n -> n = 255/3 = 85, with max data lost percentage of 33.3%.
        # redundancy = 3 -> k = 2n -> n = 255/5 = 51, with max data lost percentage of 40%.
        # redundancy = 4 -> k = 3n -> n = 255/7 = 36, with max data lost percentage of 42.9%.
        databyte = int(255/(self.redundancy*2-1))
        eccbyte = 255 - databyte
        rs = RSCodec(eccbyte)

        file_data = b''.join(data_chunks)

        file_data = bytearray(file_data)
        data_full = rs.encode(file_data)

        data_processed = []
        for i in range(255):
            for j in range(int(len(data_full)/255)+1):
                if j*255+i < len(data_full):
                    data_processed.append(data_full[(j*255)+i])
                else:
                    data_processed.append(ord('\0'))
        
        encoded_data_chunks = self.split_data(bytearray(data_processed), self.chunk_size)

        return encoded_data_chunks
        

    def rs_dec(self, data_chunks, file_size):
        """
        This function is to perform Reed Solomon decoding
        WARNING: Since this is a pure-python implementation, the decoding is very much time-consuming
        Average decoding speed for a 256KB trunk = 90 seconds.
        The speed can be optimized if using C library with more than 10x boost.
        Method:
            Reed Solomon
        Parameters:
            data_chunks
            file_size: original file size, can be retrieved from the smart contract
        Returns:
            recovered_data_chunks
        """
        # 255 - n = 2k, k = max error byte
        # redundancy = 2 -> k = n -> n = 255/3 = 85, with max data lost percentage of 33.3%.
        # redundancy = 3 -> k = 2n -> n = 255/5 = 51, with max data lost percentage of 40%.
        # redundancy = 4 -> k = 3n -> n = 255/7 = 36, with max data lost percentage of 42.9%.
        databyte = int(255/(self.redundancy*2-1))
        eccbyte = 255 - databyte
        rs = RSCodec(eccbyte)
       
        received_data = b''.join(data_chunks)

        received_data_processed = []
        for j in range(int(len(received_data)/255)+1):
            for i in range(255):
                if j+i*int(len(received_data)/255) < len(received_data):
                    received_data_processed.append(received_data[j+i*int(len(received_data)/255)])

        padded_file_size = self.chunk_size * (int(file_size / self.chunk_size) + (1 if (file_size % self.chunk_size) != 0 else 0))
        data_length = int(padded_file_size / databyte) * 255 + (padded_file_size % databyte) + eccbyte
        recovered_data = rs.decode(bytearray(received_data_processed[:data_length]))

        recovered_data = bytes(recovered_data[0])

        recovered_data_chunks = self.split_data(bytearray(recovered_data), self.chunk_size)

        return recovered_data_chunks


    def uploader_helper(self, file_content):
        """
        Parameters:
        file_content : bytearray
        sender_sk
        receiver_pk
        chunkSize: 262144 (256 KB)
        """
        sender_sk = self.private_key[2:]
        if self.shared_public_key == None:
            receiver_pk = self.public_key.to_hex()[2:]
        else:
            receiver_pk = self.shared_public_key[2:]

        #1. generate shared secret between the sender and the receiver
        shared_secret = self.gen_shared_secret(sender_sk, receiver_pk)
        #2. obtain the encryption key and the mac key
        enc_key, mac_key = self.gen_aes_mac_key(shared_secret)
        #3. split the data into chunks
        chunk_list = self.split(file_content, self.chunk_size)
        #4. encrypt the file content using the encryption key
        enc_data_list = [self.aes_enc(chunk, enc_key) for chunk in chunk_list]
        #5. redundancy using reedsolomon encoding
        rs_data_list = self.rs_enc(enc_data_list)
        #6. generate mac tag for each of the data chunk
        mac_tag_list = [self.gen_mac_tag(chunk, mac_key) for chunk in rs_data_list]
        return (rs_data_list, mac_tag_list)

    def downloader_helper(self, rs_data_list, file_size):
        """
        Parameters:
        rs_data_list
        mac_tag_list
        receiver_sk
        sender_pk
        chunkSize: 262144 (256 KB)
        Returns:
        recovered_content: bytearray
        """
        receiver_sk = self.private_key[2:]
        if self.shared_public_key == None:
            sender_pk = self.public_key.to_hex()[2:]
        else:
            sender_pk = self.shared_public_key[2:]

        #1. generate shared secret between the sender and the receiver
        shared_secret = self.gen_shared_secret(receiver_sk, sender_pk)
        #2. obtain the encryption key and the mac key
        enc_key, mac_key = self.gen_aes_mac_key(shared_secret)
        #3. check message integrity
        '''
        for i in range(len(rs_data_list)):
            rs_data_chunk = rs_data_list[i]
            mac_tag = mac_tag_list[i]
            verif_flag = ver_mac_tag(rs_data_chunk, mac_tag, mac_key)
            if not verif_flag:
                print("block {} has been tampered", i)
        '''
        #4. recover using reedsolomon redundancy method
        enc_data_list = self.rs_dec(rs_data_list, file_size)
        #5. decrypt the file chunk using the symmetric encryption key
        data_list = [self.aes_dec(chunk, enc_key) for chunk in enc_data_list]
        #6. combine the data_list
        recovered_content = self.combine(data_list)
        return recovered_content



    

##---------------- neo given
public_addr_1 = "0xD4cdE7b7480CC3228D3725FB1b8D8d4226267bA3"
private_key_1 = "0x7004f17e0cab05642f36e8ddb30b778c4ba5b6d2bc2a17338aaff3b26c55e241"
public_key_1 = "0x47d9eab50b1eabd3f493e807ba3ff22f387dcf146430e31f42c98b7ec7fbc9a40eef2080249846ca63521da29f0bcaa2049a0105cbd865d91973059a10d00daa"
##---------------- neo given 
public_addr_2 =  "0x290FABa2538A49e641e92f330CCA5afc1Ff2076C"
private_key_2 =  "0xb6c5753277f0f69e8f66196293772ce624d90a58edbfd9275ec426744ecd2dcf"           
public_key_2 = "0xa4c6fcffb1411ba3c5335f9971114603d4c58f3b53e149f1a78128de50f475f2a2b22b780c9a94c83e4de662f54fd826a239633a0e3cb0c4537f591a70a386c0"
##---------------- neo given
public_addr_3 = "0x58148928Cc24aA0f4025F171cDF958eA24143211"
private_key_3 = "0x4a561ed4832e2787355f63010ffa05453bf190b7f50b5aa8d01433a6a4fbe67a"
public_key_3 = "0x583f3823024eff1d6c19cd93a4b8fb48a3bd2d8e868ddcc26ffa99553046bbf77eb1fdb85d463b73d639ad395c7c7307d29510c1781032ef450c739d8415b1cc"
##---------------- yoyo generate
public_addr_4 ="0x28AbB50DdB82da709E2e47Eef2ECAdAC5e230e83"
private_key_4 = "0x3077020101042085af18963da3c5ae8e1b3f5315769048a1dd604968a3605fb9"
public_key_4 ="0xaf1e8c0521f5bc7ce85a3b4c2e312cc2458b62db3f0a7660c285abaa77dc09d4d83a34074648e077ad9f1f217ce23921c47e5e0d7920ef6d5087f9a9bdb6fd59"

handler = FileHandler('0xD4cdE7b7480CC3228D3725FB1b8D8d4226267bA3', '0x7004f17e0cab05642f36e8ddb30b778c4ba5b6d2bc2a17338aaff3b26c55e241')
##---------------- 
##verify that the encryption/decryptin using an symmetric aes key is correct
data_chunk = b'This is a sample data chunk that will be encrypted and decrypted using AES in CBC mode with PKCS#7 padding.'
encoded_data_chunk = handler.uploader_helper(data_chunk)

decoded_data_chunk = handler.downloader_helper(encoded_data_chunk[0], len(data_chunk))
##----------------
##reed-solomon redundancy
