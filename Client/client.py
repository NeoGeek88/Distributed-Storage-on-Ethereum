# import hashlib
import json
import inquirer
import os
import numpy as np
import requests
from file_handler import FileHandler
import connector
# import merkletools
import asyncio
from connector import Connector
import base64
from MerkleTree import MerkleTree
from dotenv import  load_dotenv

class Client:
    def __init__(self):
        self.url = "https://"
        self.file_handler = FileHandler()
        # save aes key file
        self.aes_key_file = 'aes_key.json'
        self.connector = Connector()
        self.merkletree = MerkleTree()
        self.testUrl = "http://127.0.0.3:5000"
        self.testUrl_server = "http://localhost:3000/chunk"
        self.testUrl_verify = "http://localhost:3000/chunk/verify"

        # Load environment variables from .env file
        load_dotenv()

        # Get wallet public and private keys from environment variables
        self.wallet_public_key = os.getenv("WALLET_PUBLIC_KEY")
        self.wallet_private_key = os.getenv("WALLET_PRIVATE_KEY")

        # Get file public and private keys from environment variables
        self.file_public_key = os.getenv("FILE_PUBLIC_KEY")
        self.file_private_key = os.getenv("FILE_PRIVATE_KEY")

        # Check if wallet keys exist
        if not self.wallet_public_key or not self.wallet_private_key:
            # Ask user for wallet keys
            questions = [
                inquirer.Text('wallet_public_key', message="Enter your wallet public key:"),
                inquirer.Text('wallet_private_key', message="Enter your wallet private key:")
            ]
            answers = inquirer.prompt(questions)

            # Save wallet keys to environment variables
            os.environ["WALLET_PUBLIC_KEY"] = answers['wallet_public_key']
            os.environ["WALLET_PRIVATE_KEY"] = answers['wallet_private_key']

            # Update instance variables with wallet keys
            self.wallet_public_key = answers['wallet_public_key']
            self.wallet_private_key = answers['wallet_private_key']
        else:
            print("Your wallet keys exist")

        # Check if file keys exist
        if not self.file_public_key or not self.file_private_key:
            # Ask user to generate file keys
            # TODO: Use key_generator or let user write the keys
            print("Please check the .env file and provide your file encryption keys")
            os._exit(0)
        else:
            print("Your file encryption keys exist")



    # Save AES key to local storage
    def save_aes_key(self, file_name, enc_aes_key):
        # Load existing AES key file
        if os.path.exists(self.aes_key_file):
            with open(self.aes_key_file, 'r') as f:
                aes_keys = json.load(f)
        else:
            aes_keys = {}

        # Convert the encrypted key to a base64-encoded string
        enc_aes_key_b64 = base64.b64encode(enc_aes_key).decode('utf-8')

        # Add or update the AES key for the file
        aes_keys[file_name] = enc_aes_key_b64

        # Save the updated AES key file
        with open(self.aes_key_file, 'w') as f:
            f.write(json.dumps(aes_keys))

    def get_aes_key(self, file_name):
        # Load AES key file
        if os.path.exists(self.aes_key_file):
            with open(self.aes_key_file, 'r') as f:
                aes_keys = json.load(f)
        else:
            return None

        # Return the AES key for the file
        return base64.b64decode(aes_keys.get(file_name))

    def upload_chunks_to_server(self, chunks):
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        #headers = {'Content-Type': 'application/json'}
        for chunk in chunks:
            json_data = json.dumps(chunk)
            response = requests.post(self.testUrl_server, data=json_data, headers=headers)
            if response.status_code != 200:
                break


        #response = requests.post(self.testUrl_server, data=chunks, headers = headers)
        return response

    def verify_chunks(self):
        response = requests.get(self.testUrl_verify)
        return response



    def download_chunks_from_server(self, node_ips_server):
        chunks_data = []
        for chunk_hash, node_ip in node_ips_server.items():
            url = f"http://{node_ip}:6000/chunk/{chunk_hash}"
            response = requests.get(url)
            if response.status_code == 200:
                # do something with the chunk data
                chunk_data = json.loads(response.content)
                chunk_data1 = chunk_data["chunkData"]
                #chunk_data2 = chunk_data1['chunk']
                chunk_data_bytes = base64.b64decode(chunk_data1)
                chunks_data.append(bytearray(chunk_data_bytes))

            else:
                print(f"Error downloading chunk {chunk_hash} from node {node_ip}")
        return chunks_data

    # TODO: remove chunks from server
    def remove_chunks_from_server(self, node_ips_server):
        return


    def get_available_nodes(self):
        # Mock avaiable nodes for testing , 'faf8fc10-5775-4006-a555-372ae34ade31'
        return ['a2b6f472-3f5a-490c-8af5-c840f680b598', 'aa5b2f8c-52f9-4239-a658-19abac8fe851']


    def run(self):
        while True:
            questions = [
                inquirer.List('action', message="What do you want to do?", choices=['Upload', 'Download', 'Check', 'Exit'])
            ]
            answer = inquirer.prompt(questions)

            if answer['action'] == 'Upload':
                self.upload_file()
            elif answer['action'] == 'Download':
                self.download_file()
            elif answer['action'] == 'Check':
                self.check_files()
            elif answer['action'] == 'Exit':
                break

    def read_file(self, file_path):
        with open(file_path, 'rb') as f:
            return f.read()

    '''
    Purpose: Upload the file and related information to the server and smart contract 
             after the user selects 'upload' to upload and enters the file path.
    #TODO: Modify the URL to upload to the server after Jianing provides the API.
            YOYO may not require a file path in the future, but instead require the actual file.
            Async features: pass to the server, smart contract 
    '''
    def upload_file(self):
        # Ask user for the file path
        file_path = inquirer.text(message="What's the path to the file you want to upload?")

        # Read file data
        data = self.read_file(file_path)

        # Store file data
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Encrypt, encode and split the file into chunks
        chunk_list, enc_aes_key = self.file_handler.uploadFile(file_path)

        # Save AES key to local storage
        self.save_aes_key(file_name,enc_aes_key)

        # Convert the encrypted key to a base64-encoded string
        enc_aes_key_b64 = base64.b64encode(enc_aes_key).decode('utf-8')

        #key = self.get_aes_key(file_name)

        # Store chunk list for server
        chunk_list_server = []
        for chunk in chunk_list:
            chunk_list_server.append(base64.b64encode(chunk).decode('utf-8'))

        # Hash each chunk in the list
        hashed_chunks = []
        for chunk in chunk_list:
            #hashed_chunk = MerkleTree(None).keccak256(bytes(chunk), 'bytes')
            hashed_chunk = self.merkletree.keccak256(bytes(chunk), 'bytes')
            #hashed_chunk = hashlib.sha256(chunk).hexdigest()
            hashed_chunks.append(hashed_chunk)

        # Get count number of chunks
        chunks_count = len(hashed_chunks)

        # Get available nodes and select a random subset to store chunks
        #available_nodes = self.connector.list_nodes()
        #mock available_nodes
        #available_nodes = self.get_available_nodes()

        # Get available nodes from SC
        available_nodes_metadata = json.loads(self.connector.list_nodes())

        # Get available node list
        available_nodes = []
        for available_node_metadata in available_nodes_metadata:
            available_nodes.append(available_node_metadata["node_id"])



        # randomly select nodes
        selected_nodes = np.random.choice(available_nodes, size=chunks_count, replace=True)

        # #choose hash type for merkle tree
        # mt = merkletools.MerkleTools(hash_type="sha256")

        # #Get root hash by using MerkleTool
        # mt.add_leaf(hashed_chunks)
        # mt.make_tree()
        # root_hash = mt.get_merkle_root()

        # Construct the file metadata for the smart contract
        file_metadata_merkle = {
        #     "file_name": file_name,
        #     "file_size": file_size,
        #     #"root_hash": root_hash,
            "file_chunks": [{"chunk_hash": chunk_hash, "node_id": node_id} for chunk_hash, node_id in
                            zip(hashed_chunks, available_nodes)]
        }

        # Get root hash
        mt = self.merkletree.build_merkle_tree(file_metadata_merkle["file_chunks"])
        root_hash = self.merkletree.get_roothash(mt)
        root_hash = root_hash.hex()

        # Construct the file metadata for the smart contract
        file_metadata= {
            "file_name": file_name,
            "file_size": file_size,
            "root_hash": root_hash,
            "key": enc_aes_key_b64,
            "file_chunks": [{"chunk_hash": chunk_hash.hex(), "node_id": node_id} for chunk_hash, node_id in
                            zip(hashed_chunks, selected_nodes)]
        }

        # Construct the file metadata for the server
        # file_metadata_server = {
        #     "file_name": file_name,
        #     "file_size": file_size,
        #     "root_hash": root_hash,
        #     "file_chunks": [{"chunkHash": chunk, "node_id": node_id} for chunk, node_id in
        #                     zip(chunk_list_server, selected_nodes)]
        # }

        # Construct the file metadata for the server
        file_metadata_server = [{"chunkHash": chunk_hash.hex(), "chunkData": chunk} for chunk_hash, chunk in
                            zip(hashed_chunks, chunk_list_server)]

        # Convert the metadata to JSON format
        json_metadata = json.dumps(file_metadata)

        # Convert the metadata to JSON format for server
        #json_metadata_server = json.dumps(file_metadata_server)

        # Upload the metadata to the smart contract
        # receipt = await asyncio.wait_for(connector.upload_file(json_metadata), timeout=None)
        receipt = self.connector.upload_file(json_metadata)

        if receipt['status'] == 1:
            print("File metadata uploaded to blockchain successfully!")
        else:
            print("Error uploading file to blockchain.")

        # Upload the metadata to the server
        response = self.upload_chunks_to_server(file_metadata_server)

        if response.status_code == 200:
            print("Chunks uploaded to server successfully!")
        else:
            print("Failed to upload chunks. Error code:", response.status_code)

        response_verify = self.verify_chunks()
        if response_verify.status_code == 200:
            print("all chunks are verified")
        else:
            print("verify failed")

        return



    '''
    Purpose: After the user selects the download option, return all previously uploaded files to the user
              and allow them to select which file(s) to download.
    TODO: 

          Implement async functionality with the server, smart contract, and other related components.
          Modify URL
          Decryption problem

    '''

    def download_file(self):
        # Ask the user for the download file path
        questions = [inquirer.Text('download_path', message="Where do you want to save the file?")]
        answers = inquirer.prompt(questions)
        download_path = answers['download_path']

        # Get the files metadata from the network
        files_metadata = json.loads(self.connector.list_file())

        # Let the user choose which file to download
        choices = [file_metadata["file_name"] for file_metadata in files_metadata]
        questions = [inquirer.List('file_name', message="Which file do you want to download?", choices=choices)]
        answers = inquirer.prompt(questions)

        # Store file name
        selected_file_name = answers['file_name']

        # Find the selected file metadata
        selected_file_metadata = None
        for file_metadata in files_metadata:
            if file_metadata["file_name"] == selected_file_name:
                selected_file_metadata = file_metadata
                break

        if selected_file_metadata is None:
            print("File not found.")
            return

        # Store root hash
        #selected_file_root_hash = selected_file_metadata['root_hash']



        # Retrieve the selected file metadata from smart contract
        #selected_file_metadata = json.loads(self.connector.retrieve_file(selected_file_root_hash))

        # Extract node ids from the selected file metadata
        node_ids = []
        for chunk in selected_file_metadata["file_chunks"]:
            node_ids.append(chunk["node_id"])

        # Get IP addresses of nodes
        node_ips = {}
        for node_id in node_ids:
            node_json = self.connector.get_node(node_id)
            node = json.loads(node_json)
            node_ips[node_id] = node["ip_address"]

        # Construct the file metadata for the server
        node_ips_server = {}
        for chunk in selected_file_metadata["file_chunks"]:
            node_id = chunk["node_id"]
            chunk_hash = chunk["chunk_hash"]
            ip_address = node_ips[node_id]
            node_ips_server[chunk_hash] = ip_address

        # Download chunks from server
        file_chunks = self.download_chunks_from_server(node_ips_server)

        # Get AES key
        enc_AES_key = self.get_aes_key(selected_file_name)

        # Decode, decrypt, merge into a local file
        self.file_handler.downloadFile(file_chunks, bytearray(enc_AES_key), download_path)

        return

    def check_files(self):
        # Get file metadata from smart contract
        files_metadata = json.loads(self.connector.list_file())

        # If user has no file
        if len(files_metadata) == 0:
            print("You have no file in our smart contract, please upload you file")
            return


      # Get file names for the user to choose from
        choices = [file_metadata["file_name"] for file_metadata in files_metadata]
        questions = [inquirer.List('file_name', message="Which file do you want to check?", choices=choices)]
        answers = inquirer.prompt(questions)

        # Get metadata for the selected file
        selected_file_metadata = None
        for file_metadata in files_metadata:
            if file_metadata["file_name"] == answers['file_name']:
                selected_file_metadata = file_metadata
                break

        if selected_file_metadata is None:
            print("File not found.")
            return

        # Print file metadata for the user to see
        print("File size:", selected_file_metadata["file_size"])
        print("Root hash:", selected_file_metadata["root_hash"])
        print("Node IDs of file chunks:")
        node_ids = []
        # Extract node ids from the selected file metadata
        for chunk in selected_file_metadata["file_chunks"]:
            node_ids.append(chunk["node_id"])
            print(chunk["node_id"])

        # Ask user if they want to remove the file
        questions = [inquirer.Confirm('remove_file', message="Do you want to remove the file?")]
        answers = inquirer.prompt(questions)

        if answers['remove_file']:

            # Get IP addresses of nodes
            node_ips = {}
            for node_id in node_ids:
                node_json = self.connector.get_node(node_id)
            node = json.loads(node_json)
            node_ips[node_id] = node["ip_address"]

            # Construct the file metadata for the server
            node_ips_server = {}
            for chunk in selected_file_metadata["file_chunks"]:
                node_id = chunk["node_id"]
                chunk_hash = chunk["chunk_hash"]
                ip_address = node_ips[node_id]
                node_ips_server[chunk_hash] = ip_address

            # Remove nodes from server
            # TODO: if failed, do sth
            self.remove_chunks_from_server(node_ips_server)

            # Remove the file from the smart contract
            # receipt = await asyncio.wait_for(self.connector.remove_file(selected_file_metadata["root_hash"]), timeout=None)
            receipt = self.connector.remove_file(selected_file_metadata["root_hash"])

            if receipt['status'] == 1:
                print("File removed from blockchain successfully!")
            else:
                print("Error removing file from blockchain.")





if __name__ == '__main__':
    client = Client()
    client.run()
