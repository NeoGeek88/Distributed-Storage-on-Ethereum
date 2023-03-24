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


class Client:
    def __init__(self):
        self.url = "https://"
        self.file_handler = FileHandler()
        # save aes key file
        self.aes_key_file = 'aes_key.json'
        self.connector = Connector()

    def upload_chunks_to_server(self, chunks):
        response = requests.post(self.url, data=chunks)
        return response

    def download_chunks_from_server(node_ip, chunk_hashes):
        for chunk_hash in chunk_hashes:
            url = f"http://{node_ip}/chunk/{chunk_hash}"
            response = requests.get(url)

            if response.status_code == 200:
                # do something with the chunk data
                chunk_data = response.content
            else:
                print(f"Error downloading chunk {chunk_hash} from node {node_ip}")

    def get_available_nodes(self):
        # Mock avaiable nodes for testing
        return ['node1', 'node4', 'node6']

    def run(self):
        while True:
            questions = [
                inquirer.List('action', message="What do you want to do?", choices=['Upload', 'Download', 'Exit'])
            ]
            answer = inquirer.prompt(questions)

            if answer['action'] == 'Upload':
                self.upload_file()
            elif answer['action'] == 'Download':
                self.download_file()
            elif answer['action'] == 'Exit':
                break

    def read_file(self, file_path):
        with open(file_path, 'rb') as f:
            return f.read()

    '''
    Purpose: Upload the file and related information to the server and smart contract 
             after the user selects 'upload' to upload and enters the file path.
    #TODO: Complete the functionality to upload to the server after Jianing provides the API.
            YOYO may not require a file path in the future, but instead require the actual file.
            Async features: pass to the server, smart contract 
            save aes key file
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

        # Store chunk list for server
        chunk_list_server = []
        for chunk in chunk_list:
            chunk_list_server.append(base64.b64encode(chunk).decode('utf-8'))

        # Hash each chunk in the list
        hashed_chunks = []
        for chunk in chunk_list:
            hashed_chunk = MerkleTree.keccak256(bytes(chunk), 'bytes')
            #hashed_chunk = hashlib.sha256(chunk).hexdigest()
            hashed_chunks.append(hashed_chunk)

        # Get count number of chunks
        chunks_count = len(hashed_chunks)

        # Get available nodes and select a random subset to store chunks
        available_nodes = self.connector.list_nodes()
        selected_nodes = np.random.choice(available_nodes, size=chunks_count, replace=True)

        # #choose hash type for merkle tree
        # mt = merkletools.MerkleTools(hash_type="sha256")

        # Get root hash
        mt = MerkleTree(hashed_chunks)
        root_hash = mt.get_get_roothash()

        # #Get root hash by using MerkleTool
        # mt.add_leaf(hashed_chunks)
        # mt.make_tree()
        # root_hash = mt.get_merkle_root()

        # Construct the file metadata for the smart contract
        file_metadata = {
            "file_name": file_name,
            "file_size": file_size,
            "root_hash": root_hash,
            "file_chunks": [{"chunk_hash": chunk_hash, "node_id": node_id} for chunk_hash, node_id in
                            zip(hashed_chunks, selected_nodes)]
        }

        # Construct the file metadata for the server
        file_metadata_server = {
            "file_name": file_name,
            "file_size": file_size,
            "root_hash": root_hash,
            "file_chunks": [{"chunk": chunk, "node_id": node_id} for chunk, node_id in
                            zip(chunk_list_server, selected_nodes)]
        }

        # Convert the metadata to JSON format
        json_metadata = json.dumps(file_metadata)

        # Convert the metadata to JSON format for server
        json_metadata_server = json.dumps(file_metadata_server)

        # Upload the metadata to the server
        response = self.upload_chunks_to_server(file_metadata_server)

        if response.status_code == 200:
            print("Chunks uploaded to server successfully!")
        else:
            print("Failed to upload chunks. Error code:", response.status_code)

        # Upload the metadata to the smart contract
        # receipt = await asyncio.wait_for(connector.upload_file(json_metadata), timeout=None)
        receipt = connector.upload_file(json_metadata)

        if receipt.status == 1:
            print("File metadata uploaded to blockchain successfully!")
        else:
            print("Error uploading file to blockchain.")

        # Save AES key to local storage or pass back to file_handler?
        self.file_handler.save_aes_key(file_name, enc_aes_key)

    '''
    Purpose: After the user selects the download option, return all previously uploaded files to the user
              and allow them to select which file(s) to download.
    TODO: 
          Test file_handler.download_file() , get AES key and pass to file_handler
          Implement async functionality with the server, smart contract, and other related components.
          Retrieve the chunk and node information from the smart contract 
          and send a GET request to the server using the corresponding node's IP address.
    '''

    def download_file(self):
        # Ask the user for the download file path
        questions = [inquirer.Text('download_path', message="Where do you want to save the file?")]
        answers = inquirer.prompt(questions)
        download_path = answers['download_path']

        # Get the files metadata from the network
        files_metadata = self.connector.get_files_metadata()

        # Let the user choose which file to download
        choices = [file_metadata["file_name"] for file_metadata in files_metadata]
        questions = [inquirer.List('file_name', message="Which file do you want to download?", choices=choices)]
        answers = inquirer.prompt(questions)
        selected_file_name = answers['file_name']

        # Find the metadata for the selected file
        selected_file_metadata = None
        for file_metadata in files_metadata:
            if file_metadata["file_name"] == selected_file_name:
                selected_file_metadata = file_metadata
                break

        if selected_file_metadata is None:
            # file is not exist
            print(f"Error: file {selected_file_name} not found")

        # Get the chunk hashes and node ids from the metadata
        chunk_hashes = [chunk["chunk_hash"] for chunk in selected_file_metadata["file_chunks"]]
        node_ids = [chunk["node_id"] for chunk in selected_file_metadata["file_chunks"]]

        # Download each chunk from a randomly selected node
        downloaded_chunks = []
        for chunk_hash, node_id in zip(chunk_hashes, node_ids):
            downloaded_chunk = self.network.download_chunk(chunk_hash, node_id)
            downloaded_chunks.append(downloaded_chunk)

        # Merge the downloaded chunks into the original file and save it to the specified path
        self.file_handler.downloadFile(downloaded_chunks, selected_file_metadata['enc_aes_key'], download_path)
        # merged_file = self.file_handler.downloadFile(decrypted_data, selected_file_metadata['file_name'],
        #                                              selected_file_metadata['file_size'])

        print(f"{selected_file_name} downloaded successfully to {download_path}.")


if __name__ == '__main__':
    client = Client()
    client.run()
