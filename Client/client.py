import sys
sys.path.append('../Library/Web3/')
sys.path.append('../Library/Crypto/')
import json
import inquirer
import os
import numpy as np
import requests
from connector import Connector
import base64
from MerkleTree import MerkleTree
from dotenv import load_dotenv
from FileHandler import FileHandler
import threading
import time
import random


class Client:
    def __init__(self):
        self.connector = Connector()
        self.merkletree = MerkleTree()
        INFURA_NODE_ENDPOINT = ""
        CONTRACT_ADDRESS = ""
        WALLET_PUBLIC_ADDRESS = ""
        WALLET_PRIVATE_KEY = ""
        self.chunk_size = 262144
        self.redundancy = 2

        # Check if the .env file exists
        if not os.path.exists('../.env'):
            # If the .env file does not exist, create it and write the default values
            print("There is no .env file in your directory, .env file has been created for you."
                  " Please restart your client application")
            with open('../.env', "w") as f:
                f.write(f'INFURA_NODE_ENDPOINT="{INFURA_NODE_ENDPOINT}"\n')
                f.write(f"CONTRACT_ADDRESS={CONTRACT_ADDRESS}\n")
                f.write(f"WALLET_PUBLIC_ADDRESS={WALLET_PUBLIC_ADDRESS}\n")
                f.write(f"WALLET_PRIVATE_KEY={WALLET_PRIVATE_KEY}\n")
            sys.exit(0)

        # Load environment variables from .env file
        load_dotenv('G:\\tool\\newproject\\Distributed-Storage-on-Ethereum\\.env')

        # Get INFURA NODE ENDPOINT
        self.infura_node_endpoint = os.getenv("INFURA_NODE_ENDPOINT")
        if not self.infura_node_endpoint:
            print("There is no infura node endpoint in your .env"
                  "\n Please edit you .env")
            sys.exit(0)

        # Get contract address
        self.contract_address = os.getenv("CONTRACT_ADDRESS")
        if not self.contract_address:
            print("There is contract address in your .env"
                  "\n Please edit you .env")
            sys.exit(0)

        # Get wallet public key from environment variable
        self.wallet_public_address = os.getenv("WALLET_PUBLIC_ADDRESS")
        if not self.wallet_public_address:
            print("There is no wallet public address in your .env")
            self.wallet_public_address = self.get_wallet_public_address()

        # Get wallet private key from environment variable
        self.wallet_private_key = os.getenv("WALLET_PRIVATE_KEY")
        if not self.wallet_private_key:
            print("There is no wallet private key in your .env")
            self.wallet_private_key = self.get_wallet_private_key()

        # Start the timer thread for verifying chunks
        self.timer_thread = threading.Thread(target=self.verify_chunks_periodically, args=(), daemon=True)
        self.timer_thread.start()


    # Get wallet public key from user input
    def get_wallet_public_address(self):
        questions = [inquirer.Text('wallet_public_address', message="Please enter your wallet public address")]
        answers = inquirer.prompt(questions)
        wallet_public_address = answers['wallet_public_address']
        check_if_exist_line = False
        # Save to .env file
        with open('../.env', "r") as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            if line.startswith("WALLET_PUBLIC_ADDRESS"):
                check_if_exist_line = True
                lines[i] = f"WALLET_PUBLIC_ADDRESS={wallet_public_address}\n"

        with open('../.env', "w") as f:
            f.writelines(lines)

        # If line not exist
        if not check_if_exist_line:
            with open('../.env', 'a') as f:
                f.write(f"\nWALLET_PUBLIC_ADDRESS={wallet_public_address}")

        return wallet_public_address

    # Get wallet private key from user input
    def get_wallet_private_key(self):
        questions = [inquirer.Password('wallet_private_key', message="Please enter your wallet private key")]
        answers = inquirer.prompt(questions)
        wallet_private_key = answers['wallet_private_key']
        check_if_exist_line = False
        # Save to .env file
        with open('../.env', "r") as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            if line.startswith("WALLET_PRIVATE_KEY"):
                check_if_exist_line = True
                lines[i] = f"WALLET_PRIVATE_KEY={wallet_private_key}\n"

        with open('../.env', "w") as f:
            f.writelines(lines)

        # If line not exist
        if not check_if_exist_line:
            with open('../.env', 'a') as f:
                f.write(f"\nWALLET_PRIVATE_KEY={wallet_private_key}")

        return wallet_private_key


    def upload_chunks_to_server(self, chunks):
        headers = {'Content-type': 'application/json'}

        chunks_id = []
        for chunk in chunks:
            url = f"http://{chunk['node_ip']}:{chunk['port']}/chunk"
            retry_count = 0
            while retry_count < 3:
                response = requests.post(url, data=json.dumps({
                    "chunkData": chunk['chunkData']
                }), headers=headers)
                if response.status_code == 200:
                    chunk_id = json.loads(response.content)
                    chunk_id1 = chunk_id['chunkId']
                    chunks_id.append(chunk_id1)
                    break
                else:
                    retry_count += 1
                    print("Error uploading file to blockchain. Retrying...")
            if response.status_code != 200:
                print("Failed to upload file to server after 3 attempts. Aborting upload.")
                return chunks_id, response
        return chunks_id, response

    def verify_chunks(self, node_info):
        for node in node_info:
            response = requests.get(f"http://{node['node_ip']}:{node['port']}/chunk/verify")
            if response.status_code != 200:
                return
        return response

    def download_chunks_from_server(self, node_ips_server):

        chunks_data = []
        for node in node_ips_server:
            url = f"http://{node['ip_address']}:{node['port']}/chunk/{node['chunkId']}"
            response = requests.get(url)
            if response.status_code == 200:
                # do something with the chunk data
                chunk_data = json.loads(response.content)
                chunk_data1 = chunk_data["chunkData"]
                # chunk_data2 = chunk_data1['chunk']
                chunk_data_bytes = base64.b64decode(chunk_data1)
                chunks_data.append(bytearray(chunk_data_bytes))

            else:
                # if failed?
                print(f"Error downloading chunk {node['chunkId']} from node {node['ip_address']}")
        return chunks_data


    def remove_chunks_from_server(self, nodes_info):

        for node in nodes_info:
            # Remove the failed chunk
            response = requests.delete(f"http://{node['ip_address']}:{node['port']}/chunk/{node['chunkId']}"
                                    f"/remove")
            if response.status_code != 200:
                print(f"Failed to remove chunk {node['chunkId']}")
        return response

    def get_available_nodes(self):
        # Mock avaiable nodes for testing , 'faf8fc10-5775-4006-a555-372ae34ade31'
        mock_nodes = [
            {
                "node_id": "a2b6f472-3f5a-490c-8af5-c840f680b598",
                "ip_address": "127.0.0.1",
                "domain": "example.com",
                "protocol": 0,
                "port": 5000
            },
            {
                "node_id": "aa5b2f8c-52f9-4239-a658-19abac8fe851",
                "ip_address": "127.0.0.2",
                "domain": "example.com",
                "protocol": 0,
                "port": 5000
            }
        ]
        return mock_nodes

    def run(self):
        while True:
            questions = [
                inquirer.List('action', message="What do you want to do?", choices=['Upload', 'Download', 'Check', 'Exit'])
            ]
            answer = inquirer.prompt(questions)

            if answer['action'] == 'Upload':
                upload_questions = [
                    inquirer.List('upload_action',
                                  message="Do you want to share the file or upload to the server?",
                                  choices=['Share', 'Upload to server', 'Back'])
                ]
                upload_answer = inquirer.prompt(upload_questions)

                if upload_answer['upload_action'] == 'Share':
                    self.share_file()
                elif upload_answer['upload_action'] == 'Upload to server':
                    self.upload_file()
                else:
                    continue
            elif answer['action'] == 'Download':
                self.download_file()
            elif answer['action'] == 'Check':
                self.check_files()
            elif answer['action'] == 'Exit':
                break

    def read_file(self, file_path):
        with open(file_path, 'rb') as f:
            return f.read()

    def verify_chunks_periodically(self):
        # Pass wallet public address and private key to File Handler
        self.new_file_handler = FileHandler(self.wallet_public_address, f'0x{self.wallet_private_key}')

        # Define the interval between verification checks (in seconds)
        interval = 60

        while True:
            # Wait for the specified interval
            time.sleep(interval)

            if len(json.loads(self.connector.list_file())) == 0:
                return
            # Get the files metadata from the network
            files_metadata = json.loads(self.connector.list_file())

            # Randomly select a file
            selected_file_metadata = random.choice(files_metadata)

            # Randomly select a chunk from the file
            #selected_chunk_metadata = random.choice(selected_file_metadata["file_chunks"])
            selected_chunk_metadata = selected_file_metadata["file_chunks"][3]


            # Get the chunk id of the selected chunk
            selected_chunk_id = selected_chunk_metadata["chunk_id"]

            # Get the node ID of the selected chunk
            selected_node_id = selected_chunk_metadata["node_id"]

            # Get the IP address of the node
            selected_node_metadata = json.loads(self.connector.get_node(selected_node_id))
            selected_node_ip = selected_node_metadata["ip_address"]

            # Get the port of the node
            selected_node_port = selected_node_metadata["port"]

            # Call Server function to pass the id of the chunk to server and get the hash after server calculation
            response = requests.get(f"http://{selected_node_ip}:{selected_node_port}/chunk/{selected_chunk_id}/check")

            if response.status_code == 200:
                chunk_hash = json.loads(response.content)
                chunk_hash1 = chunk_hash['hash']


                # Get the index of the selected chunk
                index = selected_file_metadata["file_chunks"].index(selected_chunk_metadata)

                # Convert root hash and chunk hash into bytes32
                chunk_root_hash = selected_file_metadata["root_hash"]

                # Get the Merkle proof for the selected chunk
                merkle_proof = self.connector.merkle_proof(f'0x{chunk_root_hash}',
                                                           f'0x{chunk_root_hash}',
                                                           index)

            if merkle_proof == "true":
                print(f"Chunk {selected_chunk_id} from file {selected_file_metadata['file_name']} is verified")
                continue
            elif merkle_proof == "false" or response.status_code == 408:
                print(
                    f"Chunk {selected_chunk_id} from file {selected_file_metadata['file_name']} failed verification")

                # Extract node ids from the selected file metadata
                nodes_selected_file = []
                for chunk in selected_file_metadata["file_chunks"]:
                    # node_ids.append(chunk["node_id"])
                    nodes_selected_file.append(json.loads(self.connector.get_node(chunk["node_id"])))

                nodes_info = [{
                    "node_id": node["node_id"],
                    "ip_address": node["ip_address"],
                    "port": node["port"],
                    "chunkId": chunk["chunk_id"]}
                    for chunk, node in zip(selected_file_metadata["file_chunks"], nodes_selected_file)]

                # Get available nodes and select a random subset to store chunks
                available_nodes_sc = json.loads(self.connector.list_nodes())

                # Randomly select node
                random_node = random.choice(available_nodes_sc)

                # Get node info
                node_info = json.loads(self.connector.get_node(random_node["node_id"]))

                # Download chunks from server
                file_chunks = self.download_chunks_from_server(nodes_info)

                # Replace the invalid chunk with zeros
                corrected_chunk = b'\x00' * self.chunk_size
                file_chunks[index] = bytearray(corrected_chunk)

                # Get file size and name
                file_size = selected_file_metadata['file_size']

                # Recover the file by using downloader_helper
                recovered_chunks = self.new_file_handler.recover_helper(file_chunks, file_size)

                # base64decode chunk
                b64_recover_chunk = base64.b64encode(recovered_chunks[index]).decode(('utf-8'))

                # Upload the recovered chunk to server
                headers = {'Content-type': 'application/json'}
                url = f"http://{node_info['ip_address']}:{node_info['port']}/chunk"
                response_recovered = requests.post(url, data=json.dumps({
                    "chunkData": b64_recover_chunk
                }), headers=headers)

                if response_recovered.status_code == 200:
                    chunk_id = json.loads(response_recovered.content)
                    chunk_id1 = chunk_id['chunkId']
                    print("Uploaded recovered chunk to server successfully ")
                else:
                    print("Failed to upload recovered chunk")

                # Remove the failed chunk
                response = requests.delete(f"http://{selected_node_ip}:{selected_node_port}/chunk/{selected_chunk_id}"
                                        f"/remove")
                if response == 200:
                    print("Remove failed chunk successfully")

                # Update the file metadata recording to the recovered_chunk
                selected_file_metadata["file_chunks"][index]["chunk_id"] = chunk_id1
                selected_file_metadata["file_chunks"][index]["node_id"] = node_info["node_id"]

                # Add 0x to hashed chunks and root_hash
                selected_file_metadata["root_hash"] = "0x" + selected_file_metadata["root_hash"]
                selected_file_metadata["file_chunks"] = [{"chunk_hash": "0x" + chunk["chunk_hash"], "node_id": chunk["node_id"],
                                                 "chunk_id": chunk["chunk_id"]} for chunk in
                                                selected_file_metadata["file_chunks"]]

                # Upload the file metadata to blockchain
                receipt = self.connector.update_file(json.dumps(selected_file_metadata))

                if receipt['status'] == 1:
                    print("File metadata updated to blockchain successfully")
                else:
                    print("Failed to update file metadata")

                response_verify = requests.get(f"http://{node_info['node_ip']}:{node_info['port']}/chunk/verify")

                print("Failed verification fixed")
            else:
                print(f"Server down or chunk does not exist. Error:{response.status_code}")
                return

    '''
    Purpose: Upload the file and related information to the server and smart contract 
             after the user selects 'upload' to upload and enters the file path.
    '''
    def upload_file(self):
        # Pass wallet public address and private key to File Handler
        self.new_file_handler = FileHandler(self.wallet_public_address, f'0x{self.wallet_private_key}')

        # Ask user for the file path
        file_path = inquirer.text(message="What's the path to the file you want to upload?")

        # Read file data
        data = self.read_file(file_path)

        # Store file data
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Split, Encrypt, Encode the file
        chunk_list = self.new_file_handler.uploader_helper(data)

        # Store chunk list for server
        chunk_list_server = []
        for chunk in chunk_list[0]:
            chunk_list_server.append(base64.b64encode(chunk).decode('utf-8'))

        # Hash each chunk in the list
        hashed_chunks = []
        for chunk in chunk_list[0]:
            hashed_chunk = self.merkletree.keccak256(bytes(chunk), 'bytes')
            hashed_chunks.append(hashed_chunk)

        # Get count number of chunks
        chunks_count = len(hashed_chunks)

        # Get available nodes and select a random subset to store chunks
        available_nodes_sc = json.loads(self.connector.list_nodes())

        selected_nodes = []
        for i in range(chunks_count):
            random_node = random.choice(available_nodes_sc)
            selected_nodes.append(random_node)

        # Construct the file metadata for the smart contract
        file_metadata_merkle = {

            "file_chunks": [{"chunk_hash": chunk_hash, "node_id": selected_node["node_id"]} for chunk_hash, selected_node in
                            zip(hashed_chunks, selected_nodes)]
        }

        # Get current timestamp
        time_stamp = int(time.time())

        # Get root hash
        mt = self.merkletree.build_merkle_tree(file_metadata_merkle["file_chunks"])
        root_hash = self.merkletree.get_roothash(mt)
        root_hash = root_hash.hex()

        # Construct the file metadata for the server
        file_metadata_server = [{"chunkHash": chunk_hash.hex(),
                                 "chunkData": chunk,
                                 "node_ip": selected_node["ip_address"],
                                 "port": selected_node["port"]
                                 } for chunk_hash, chunk, selected_node in
                            zip(hashed_chunks, chunk_list_server, selected_nodes)]

        # Upload the metadata to the server
        chunks_id, response = self.upload_chunks_to_server(file_metadata_server)
        if response.status_code == 200:
            print("Chunks uploaded to server successfully!")
        else:
            print("Failed to upload chunks. Error code:", response.status_code)
            return

        # Construct the file metadata for the smart contract
        file_metadata = {
            "file_name": file_name,
            "file_size": file_size,
            "root_hash": root_hash,
            "chunk_size": self.chunk_size,
            "redundancy": self.redundancy,
            "timestamp": time_stamp,
            "file_chunks": [{"chunk_hash": chunk_hash.hex(), "node_id": selected_node['node_id'],
                             "chunk_id":chunk_id}
                            for chunk_hash, selected_node, chunk_id in
                            zip(hashed_chunks, selected_nodes, chunks_id)]
        }

        # Convert the metadata to JSON format
        json_metadata = json.dumps(file_metadata)

        # Set up retry count
        retry_count = 0

        # Upload the metadata to the smart contract, retrying up to 3 times if necessary
        while retry_count < 3:
            receipt = self.connector.upload_file(json_metadata)

            if receipt['status'] == 1:
                print("File metadata uploaded to blockchain successfully!")
                break  # Exit the loop if successful
            else:
                retry_count += 1
                print("Error uploading file to blockchain. Retrying...")

        # Check if the upload was successful after retrying
        if receipt['status'] != 1:
            print("Failed to upload file metadata to blockchain after 3 attempts. Aborting upload.")

        # Verify
        response_verify = self.verify_chunks(file_metadata_server)
        if response_verify.status_code == 200:
            print("all chunks are verified")
        else:
            print("verify failed")

        return





    '''
    Purpose: After the user selects the download option, return all previously uploaded files to the user
              and allow them to select which file(s) to download.
    '''

    def download_file(self):
        # Ask the user for the download file path
        questions = [inquirer.Text('download_path', message="Where do you want to save the file?")]
        answers = inquirer.prompt(questions)
        download_path = answers['download_path']

        # Get the files metadata from the network
        files_metadata = json.loads(self.connector.list_file())

        # Let the user choose which file to download
        choices = [
            f"{file_metadata['file_name']} ({time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(int(file_metadata['timestamp'])))}) ({file_metadata['root_hash']})"
            for file_metadata in files_metadata]
        questions = [inquirer.List('choice', message="Which file do you want to download?", choices=choices)]
        answers = inquirer.prompt(questions)

        share_questions = [
            inquirer.List('share_action',
                          message="Is this file your own file or is it a shared file?",
                          choices=['Your own file', 'Shared file'])
        ]

        share_answer = inquirer.prompt(share_questions)

        if share_answer['share_action'] == 'Your own file':
            # Pass wallet public address and private key to File Handler
            self.new_file_handler = FileHandler(self.wallet_public_address, f'0x{self.wallet_private_key}')
        elif share_answer['share_action'] == 'Shared file':
            # Get the public key
            sender_share_public_key = inquirer.text(message="Please enter the sender's public key")

            # Pass wallet public address, private key, and sender's public key to File Handler
            self.new_file_handler = FileHandler(self.wallet_public_address, f'0x{self.wallet_private_key}',
                                                shared_public_key=sender_share_public_key)

        # Get the selected file root hash
        selected_file_root_hash = answers['choice'].split(") (")[1][:-1]

        # Find the selected file metadata
        selected_file_metadata = None
        for file_metadata in files_metadata:
            if file_metadata["root_hash"] == selected_file_root_hash:
                selected_file_metadata = file_metadata
                break

        file_size = selected_file_metadata['file_size']

        if selected_file_metadata is None:
            print("File not found.")
            return

        # Extract node ids from the selected file metadata
        nodes_selected_file = []
        for chunk in selected_file_metadata["file_chunks"]:
            #node_ids.append(chunk["node_id"])
            nodes_selected_file.append(json.loads(self.connector.get_node(chunk["node_id"])))

        nodes_info = [{
            "node_id":node["node_id"],
            "ip_address":node["ip_address"],
            "port":node["port"],
            "chunkId":chunk["chunk_id"]}
            for chunk, node in zip(selected_file_metadata["file_chunks"], nodes_selected_file)]

        # Download chunks from server
        file_chunks = self.download_chunks_from_server(nodes_info)

        data = self.new_file_handler.downloader_helper(file_chunks, file_size)

        # Construct the file path
        file_path = os.path.join(download_path, selected_file_metadata['file_name'])

        with open(file_path, 'wb') as f:
            f.write(data)

        return

    def check_files(self):
        # Get file metadata from smart contract
        files_metadata = json.loads(self.connector.list_file())

        # If user has no file
        if len(files_metadata) == 0:
            print("You have no file in our smart contract, please upload you file")
            return

        # Let the user choose which file to download
        choices = [
            f"{file_metadata['file_name']} ({time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(int(file_metadata['timestamp'])))}) ({file_metadata['root_hash']})"
            for file_metadata in files_metadata]
        questions = [inquirer.List('choice', message="Which file do you want to check?", choices=choices)]
        answers = inquirer.prompt(questions)

        # Get the selected file root hash
        selected_file_root_hash = answers['choice'].split(") (")[1][:-1]

        # Find the selected file metadata
        selected_file_metadata = None
        for file_metadata in files_metadata:
            if file_metadata["root_hash"] == selected_file_root_hash:
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

            # Extract node ids from the selected file metadata
            nodes_selected_file = []
            for chunk in selected_file_metadata["file_chunks"]:
                # node_ids.append(chunk["node_id"])
                nodes_selected_file.append(json.loads(self.connector.get_node(chunk["node_id"])))

            nodes_info = [{
                "node_id": node["node_id"],
                "ip_address": node["ip_address"],
                "port": node["port"],
                "chunkId": chunk["chunk_id"]}
                for chunk, node in zip(selected_file_metadata["file_chunks"], nodes_selected_file)]
            # Remove file from server
            response = self.remove_chunks_from_server(nodes_info)

            if response.status_code != 200:
                print(f"Failed to remove file {selected_file_metadata['file_name']}")
            else:
                print(f"Remove file {selected_file_metadata['file_name']} successfully")

            # Set up retry count
            retry_count = 0

            # Upload the metadata to the smart contract, retrying up to 3 times if necessary
            while retry_count < 3:
                receipt = self.connector.remove_file(f'0x{selected_file_metadata["root_hash"]}')

                if receipt['status'] == 1:
                    print(f"Remove file {selected_file_metadata['file_name']} from blockchain successfully!")
                    break  # Exit the loop if successful
                else:
                    retry_count += 1
                    print("Error uploading file to blockchain. Retrying...")

            # Check if the upload was successful after retrying
            if receipt['status'] != 1:
                print("Failed to remove file metadata from blockchain after 3 attempts. Aborting upload.")

            return

    def share_file(self):
        # Ask user for the file path
        file_path = inquirer.text(message="What's the path to the file you want to upload?")

        # Read file data
        data = self.read_file(file_path)

        # Store file data
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Get the public key
        receiver_share_public_key = inquirer.text(message="Please enter the receiver's public key")

        # Get the receiver's public address
        receiver_eth_public_address = self.new_file_handler.gen_eth_public_address(bytes.fromhex(receiver_share_public_key[2:]))

        # Update the File_Handler object
        self.new_file_handler = FileHandler(self.wallet_public_address, f'0x{self.wallet_private_key}',
                              shared_public_key=receiver_share_public_key)
        # Split, Encrypt, Encode the file
        chunk_list = self.new_file_handler.uploader_helper(data)

        # Store chunk list for server
        chunk_list_server = []
        for chunk in chunk_list[0]:
            chunk_list_server.append(base64.b64encode(chunk).decode('utf-8'))

        # Hash each chunk in the list
        hashed_chunks = []
        for chunk in chunk_list[0]:
            hashed_chunk = self.merkletree.keccak256(bytes(chunk), 'bytes')
            hashed_chunks.append(hashed_chunk)

        # Get count number of chunks
        chunks_count = len(hashed_chunks)

        # Get available nodes and select a random subset to store chunks
        available_nodes_sc = json.loads(self.connector.list_nodes())

        # # Shuffle the list of nodes randomly depends on the chunks_count
        selected_nodes = []
        for i in range(chunks_count):
            random_node = random.choice(available_nodes_sc)
            selected_nodes.append(random_node)

        # Construct the file metadata for the smart contract
        file_metadata_merkle = {

            "file_chunks": [{"chunk_hash": chunk_hash, "node_id": selected_node["node_id"]} for chunk_hash, selected_node in
                            zip(hashed_chunks, selected_nodes)]
        }

        # Get current timestamp
        time_stamp = int(time.time())

        # Get root hash
        mt = self.merkletree.build_merkle_tree(file_metadata_merkle["file_chunks"])
        root_hash = self.merkletree.get_roothash(mt)
        root_hash = root_hash.hex()

        # Construct the file metadata for the server
        file_metadata_server = [{"chunkHash": chunk_hash.hex(),
                                 "chunkData": chunk,
                                 "node_ip": selected_node["ip_address"],
                                 "port": selected_node["port"]
                                 } for chunk_hash, chunk, selected_node in
                            zip(hashed_chunks, chunk_list_server, selected_nodes)]

        # # Convert the metadata to JSON format for server
        # json_metadata_server = json.dumps(file_metadata_server)

        # Upload the metadata to the server
        chunks_id, response = self.upload_chunks_to_server(file_metadata_server)
        if response.status_code == 200:
            print("Chunks uploaded to server successfully!")
        else:
            print("Failed to upload chunks. Error code:", response.status_code)

        # Construct the file metadata for the smart contract
        file_metadata= {
            "file_name": file_name,
            "file_size": file_size,
            "root_hash": root_hash,
            "chunk_size": self.chunk_size,
            "redundancy": self.redundancy,
            "timestamp": time_stamp,
            "file_chunks": [{"chunk_hash": chunk_hash.hex(), "node_id": selected_node['node_id'],
                             "chunk_id":chunk_id}
                            for chunk_hash, selected_node, chunk_id in
                            zip(hashed_chunks, selected_nodes, chunks_id)]
        }

        # Convert the metadata to JSON format
        json_metadata = json.dumps(file_metadata)

        # Set up retry count
        retry_count = 0

        # Upload the metadata to the smart contract, retrying up to 3 times if necessary
        while retry_count < 3:
            receipt = self.connector.add_shared_file(receiver_eth_public_address, json_metadata)

            if receipt['status'] == 1:
                print("File metadata uploaded to blockchain successfully!")
                break  # Exit the loop if successful
            else:
                retry_count += 1
                print("Error uploading file to blockchain. Retrying...")

        # Check if the upload was successful after retrying
        if receipt['status'] != 1:
            print("Failed to upload file metadata to blockchain after 3 attempts. Aborting upload.")

        # Verify
        response_verify = self.verify_chunks(file_metadata_server)
        if response_verify.status_code == 200:
            print("all chunks are verified")
        else:
            print("verify failed")
        return


if __name__ == '__main__':
    client = Client()
    client.run()
