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
        self.url = "https://"
        # save aes key file
        self.aes_key_file = 'aes_key.json'
        self.connector = Connector()
        self.merkletree = MerkleTree()
        self.testUrl = "http://127.0.0.3:5000"
        self.testUrl_server = "http://localhost:3000/chunk"
        self.testUrl_verify = "http://localhost:3000/chunk/verify"
        #self.new_file_handler = try6.file_handler()
        INFURA_NODE_ENDPOINT = "https://sepolia.infura.io/v3/325c2e4f72b743a99bf8325760da19c5"
        CONTRACT_ADDRESS = "0xc0c335b31df7c7bbe9298ad2b2bacd0777ebbdd4"
        WALLET_PUBLIC_ADDRESS = ""
        WALLET_PRIVATE_KEY = ""
        #FILE_PUBLIC_KEY = ""
        self.chunk_size = 262144
        self.redundancy = 2

        # Check if the .env file exists
        if not os.path.exists('../.env'):
            # If the .env file does not exist, create it and write the default values
            print("There is no .env file in your directory, .env file has been created for you. Please restart")
            with open('../.env', "w") as f:
                f.write(f'INFURA_NODE_ENDPOINT="{INFURA_NODE_ENDPOINT}"\n')
                f.write(f"CONTRACT_ADDRESS={CONTRACT_ADDRESS}\n")
                f.write(f"WALLET_PUBLIC_ADDRESS={WALLET_PUBLIC_ADDRESS}\n")
                f.write(f"WALLET_PRIVATE_KEY={WALLET_PRIVATE_KEY}\n")
                #f.write(f"FILE_PUBLIC_KEY={FILE_PUBLIC_KEY}\n")
            return

        # Load environment variables from .env file
        load_dotenv('G:\\tool\\newproject\\Distributed-Storage-on-Ethereum\\.env')

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

        # Pass wallet public address and private key to File Handler
        self.new_file_handler = FileHandler(self.wallet_public_address, f'0x{self.wallet_private_key}')

        # Start the timer thread for verifying chunks
        self.timer_thread = threading.Thread(target=self.verify_chunks_periodically, args=(), daemon=True)
        self.timer_thread.start()

    def verify_chunks_periodically(self):
        # Define the interval between verification checks (in seconds)
        interval = 3600

        while True:
            # Wait for the specified interval
            time.sleep(interval)

            # Get the files metadata from the network
            files_metadata = json.loads(self.connector.list_file())

            # Randomly select a file
            selected_file_metadata = random.choice(files_metadata)

            # Randomly select a chunk from the file
            selected_chunk_metadata = random.choice(selected_file_metadata["file_chunks"])

            # Get the hash of the selected chunk
            selected_chunk_hash = selected_chunk_metadata["chunk_hash"]

            # Get the node ID of the selected chunk
            selected_node_id = selected_chunk_metadata["node_id"]

            # Get the IP address of the node
            selected_node_metadata = json.loads(self.connector.get_node(selected_node_id))
            selected_node_ip = selected_node_metadata["ip_address"]

            # Call Server function to pass the hash of the chunk to server and get the hash after server calculation
            # TODO: according to server's hask related api to input hash and get hash
            response = requests.post(f"http://{selected_node_ip}:3000/chunk/{selected_chunk_hash}",
                                     data=json.dump(selected_node_ip))
            if response.status_code != 200:
                print("Error getting chunk hash")
                continue
            chunk_hash = response.json()["hash"]

            # Get the index of the selected chunk
            index = selected_file_metadata["file_chunks"].index(selected_chunk_metadata)

            # Get the Merkle proof for the selected chunk
            merkle_proof = self.connector.merkle_proof(selected_file_metadata["root_hash"], chunk_hash, index)

            if merkle_proof:
                print(f"Chunk {selected_chunk_hash} from file {selected_file_metadata['file_name']} is verified")
                continue
            else:
                print(f"Chunk {selected_chunk_hash} from file {selected_file_metadata['file_name']} failed verification")

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

                # Replace the invalid chunk with zeros
                corrected_chunk = b'\x00' * self.chunk_size
                file_chunks[index] = corrected_chunk

                # Recover the file by using downloader_helper
                data = self.new_file_handler.downloader_helper(file_chunks, len(file_chunks))

                file_name = selected_file_metadata['file_name']
                file_size = selected_file_metadata['file_size']

                # Split, Encrypt, Encode the file by using uploader_helper
                chunk_list = self.new_file_handler.uploader_helper(data)

                # Store chunk for server
                chunk_server = base64.b64encode(chunk_list[0][index]).decode('utf-8')
                # Hash chunk
                hashed_chunk = self.merkletree.keccak256(bytes(chunk_list[0][index]), 'bytes')

                # # Get available nodes and select a random node to store chunk
                # available_nodes = self.connector.list_nodes()

                # mock available_nodes
                available_nodes_mock = self.get_available_nodes()

                # Get available node list
                available_nodes = {}
                available_nodes_id = []
                for available_node_metadata in available_nodes_mock:
                    node_id = available_node_metadata["node_id"]
                    node_ip = available_node_metadata["ip_address"]
                    available_nodes_id.append(node_id)
                    available_nodes[node_id] = node_ip

                # randomly select node
                selected_nodes_id = np.random.choice(available_nodes_id, size=1, replace=True)

                # Get current timestamp
                time_stamp = int(time.time())

                # Construct the file metadata for the smart contract
                file_chunks_SC = selected_file_metadata["file_chunks"]
                file_chunks_SC[index]["node_id"] = selected_nodes_id
                selected_file_metadata["file_chunks"] = file_chunks_SC
                selected_file_metadata["timestamp"] = time_stamp

                # Construct the file metadata for the server
                file_chunk_server = {
                    "chunkHash": hashed_chunk.hex(),
                    "chunkData": chunk_server
                }

                # Convert the metadata to JSON format for SC
                json_selected_file_metadata = json.dumps(selected_file_metadata)

                # Convert the metadata to JSON format for server
                json_file_chunk_server = json.dumps(file_chunk_server)

                headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
                url = f"http://{available_nodes[selected_node_id]}:3000/chunk"
                retry_count = 0
                while retry_count < 3:
                    response = requests.post(url, data=json_file_chunk_server, headers=headers)

                    if response.status_code == 200:
                        print("The chunk uploaded to server successfully!")
                        break # Exit the loop if successful
                    else:
                        retry_count += 1
                        print("Error uploading the chunk to server. Retrying...")

                # Check if the upload was successful after retrying
                if response.status_code != 200:
                    print("Server down")
                    continue

                # Set up retry count
                retry_count = 0

                # Upload the metadata to the smart contract, retrying up to 3 times if necessary
                while retry_count < 3:
                    receipt = self.connector.upload_file(json_selected_file_metadata)

                    if receipt['status'] == 1:
                        print("File metadata updated to blockchain successfully!")
                        break  # Exit the loop if successful
                    else:
                        retry_count += 1
                        print("Error updating file to blockchain. Retrying...")

                # Check if the upload was successful after retrying
                if receipt['status'] != 1:
                    print("Failed to update file metadata to blockchain after 3 attempts. Aborting upload.")
                    continue

                print("Failed verification fixed")

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

    # # Get file public key by passing wallet_private_key
    # def get_file_public_key(self, wallet_private_key):
    #     # Generate key by pass wallet_private_key
    #     file_public_key = str(try6.gen_eth_public_key(wallet_private_key))
    #     check_if_exist_line = False
    #     # Save to .env file
    #     with open('../.env', "r") as f:
    #         lines = f.readlines()
    #     for i, line in enumerate(lines):
    #         if line.startswith("FILE_PUBLIC_KEY"):
    #             check_if_exist_line = True
    #             lines[i] = f"FILE_PUBLIC_KEY={file_public_key[2:]}\n"
    #
    #     with open('../.env', "w") as f:
    #         f.writelines(lines)
    #
    #     # If line not exist
    #     if not check_if_exist_line:
    #         with open('../.env', 'a') as f:
    #             f.write(f"\nFILE_PUBLIC_KEY={file_public_key[2:]}")
    #
    #     return file_public_key


    # # Save AES key to local storage
    # def save_aes_key(self, file_name, enc_aes_key):
    #     # Load existing AES key file
    #     if os.path.exists(self.aes_key_file):
    #         with open(self.aes_key_file, 'r') as f:
    #             aes_keys = json.load(f)
    #     else:
    #         aes_keys = {}
    #
    #     # Convert the encrypted key to a base64-encoded string
    #     enc_aes_key_b64 = base64.b64encode(enc_aes_key).decode('utf-8')
    #
    #     # Add or update the AES key for the file
    #     aes_keys[file_name] = enc_aes_key_b64
    #
    #     # Save the updated AES key file
    #     with open(self.aes_key_file, 'w') as f:
    #         f.write(json.dumps(aes_keys))

    # def get_aes_key(self, file_name):
    #     # Load AES key file
    #     if os.path.exists(self.aes_key_file):
    #         with open(self.aes_key_file, 'r') as f:
    #             aes_keys = json.load(f)
    #     else:
    #         return None
    #
    #     # Return the AES key for the file
    #     return base64.b64decode(aes_keys.get(file_name))

    def upload_chunks_to_server(self, chunks):
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        #headers = {'Content-Type': 'application/json'}
        # for chunk in chunks:
        #     json_data = json.dumps(chunk)
        #     response = requests.post(self.testUrl_server, data=json_data, headers=headers)
        #     if response.status_code != 200:
        #         break

        for chunk in chunks:
            url = f"http://{chunk['node_ip']}:{chunk['port']}/chunk"
            retry_count = 0
            while retry_count < 3:
                response = requests.post(url, data=json.dumps({
                    "chunkHash": chunk['chunkHash'],
                    "chunkData": chunk['chunkData']
                }), headers=headers)
                if response.status_code == 200:
                    break
                else:
                    retry_count += 1
                    print("Error uploading file to blockchain. Retrying...")
            if response.status_code != 200:
                print("Failed to upload file to server after 3 attempts. Aborting upload.")
                return response
        return response

    def verify_chunks(self, node_info):
        for node in node_info:
            response = requests.get(f"http://{node['node_ip']}:{node['port']}/chunk/verify")
            if response.status_code != 200:
                return
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
                # TODO: if failed, 50%? three times count?
                print(f"Error downloading chunk {chunk_hash} from node {node_ip}")

        chunks_data = []
        for node in node_ips_server:
            url = f"http://{node['ip_address']}:{node['port']}/chunk/{node['chunk_hash']}"
            response = requests.get(url)
            if response.status_code == 200:
                # do something with the chunk data
                chunk_data = json.loads(response.content)
                chunk_data1 = chunk_data["chunkData"]
                # chunk_data2 = chunk_data1['chunk']
                chunk_data_bytes = base64.b64decode(chunk_data1)
                chunks_data.append(bytearray(chunk_data_bytes))

            else:
                # TODO: if failed, 50%? three times count?
                print(f"Error downloading chunk {chunk_hash} from node {node_ip}")
        return chunks_data




    # TODO: remove chunks from server
    def remove_chunks_from_server(self, node_ips_server):
        return

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

        # Split, Encrypt, Encode the file
        chunk_list = self.new_file_handler.uploader_helper(data)

        # Save AES key to local storage
        #self.save_aes_key(file_name,enc_aes_key)

        # Convert the encrypted key to a base64-encoded string
        #enc_aes_key_b64 = base64.b64encode(enc_aes_key).decode('utf-8')

        #key = self.get_aes_key(file_name)

        # Store chunk list for server
        chunk_list_server = []
        for chunk in chunk_list[0]:
            chunk_list_server.append(base64.b64encode(chunk).decode('utf-8'))

        # Hash each chunk in the list
        hashed_chunks = []
        for chunk in chunk_list[0]:
            #hashed_chunk = MerkleTree(None).keccak256(bytes(chunk), 'bytes')
            hashed_chunk = self.merkletree.keccak256(bytes(chunk), 'bytes')
            hashed_chunks.append(hashed_chunk)

        # Get count number of chunks
        chunks_count = len(hashed_chunks)

        # Get available nodes and select a random subset to store chunks
        available_nodes_sc = json.loads(self.connector.list_nodes())
        # #mock available_nodes
        # available_nodes_mock = self.get_available_nodes()

        # Get available nodes from SC
        #available_nodes_metadata = json.loads(self.connector.list_nodes())

        # Get available node list
        # available_nodes_node_id = []
        # for available_node_metadata in available_nodes_mock:
        #     available_nodes_node_id.append(available_node_metadata["node_id"])

        # # Shuffle the list of nodes randomly depends on the chunks_count
        # selected_nodes = random.sample(available_nodes_sc, k=chunks_count)
        selected_nodes = []
        for i in range(chunks_count):
            random_node = random.choice(available_nodes_sc)
            selected_nodes.append(random_node)

        # # Get available node list
        # available_nodes = {}
        # available_nodes_id = []
        # for available_node_metadata in available_nodes_sc:
        #     node_id = available_node_metadata["node_id"]
        #     node_ip = available_node_metadata["ip_address"]
        #     available_nodes_id.append(node_id)
        #     available_nodes[node_id] = node_ip

        # # randomly select nodes
        # selected_nodes_id = np.random.choice(available_nodes_id, size=chunks_count, replace=True)

        # Get node ips
        #available_nodes_time = []


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

        # Construct the file metadata for the smart contract
        file_metadata= {
            "file_name": file_name,
            "file_size": file_size,
            "root_hash": root_hash,
            "chunk_size": self.chunk_size,
            "redundancy": self.redundancy,
            "timestamp": time_stamp,
            "file_chunks": [{"chunk_hash": chunk_hash.hex(), "node_id": selected_node['node_id']} for chunk_hash, selected_node in
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

        # # Get node IP from selected nodes
        # selected_nodes_ip = []
        # for selected_node_id in selected_nodes_id:
        #     selected_nodes_ip.append(available_nodes[selected_node_id])

        # Construct the file metadata for the server
        file_metadata_server = [{"chunkHash": chunk_hash.hex(),
                                 "chunkData": chunk,
                                 "node_ip": selected_node["ip_address"],
                                 "port": selected_node["port"]
                                 } for chunk_hash, chunk, selected_node in
                            zip(hashed_chunks, chunk_list_server, selected_nodes)]

        # Convert the metadata to JSON format
        json_metadata = json.dumps(file_metadata)

        # # Convert the metadata to JSON format for server
        # json_metadata_server = json.dumps(file_metadata_server)

        # Upload the metadata to the server
        response = self.upload_chunks_to_server(file_metadata_server)
        if response.status_code == 200:
            print("Chunks uploaded to server successfully!")
        else:
            print("Failed to upload chunks. Error code:", response.status_code)

        # Upload the metadata to the smart contract
        #receipt = await asyncio.wait_for(connector.upload_file(json_metadata), timeout=None)

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
        # choices = [file_metadata["file_name"] for file_metadata in files_metadata]
        # questions = [inquirer.List('file_name', message="Which file do you want to download?", choices=choices)]
        # answers = inquirer.prompt(questions)

        # Let the user choose which file to download
        choices = [
            f"{file_metadata['file_name']} ({time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(int(file_metadata['timestamp'])))}) ({file_metadata['root_hash']})"
            for file_metadata in files_metadata]
        questions = [inquirer.List('choice', message="Which file do you want to download?", choices=choices)]
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
        node_info = [{
            "node_id",
            "ip_address",
            "port",
            "chunkHash"
        }]

        for node_id in node_ids:
            node_json = self.connector.get_node(node_id)
            node = json.loads(node_json)
            #node_ips[node_id] = node["ip_address"]
            node_info['node_id'] = node['node_id']
            node_info['ip_address'] = node['ip_address']
            node_info['port'] = node['port']

        # Construct the file metadata for the server
        # node_ips_server = {}
        # for chunk in selected_file_metadata["file_chunks"]:
        #     node_id = chunk["node_id"]
        #     chunk_hash = chunk["chunk_hash"]
        #     ip_address = node_ips[node_id]
        #     node_ips_server[chunk_hash] = ip_address

        for chunk in selected_file_metadata["file_chunks"]:
            node_info["chunkHash"] = chunk["chunk_hash"]


        # Download chunks from server
        file_chunks = self.download_chunks_from_server(node_info)

        # Get AES key
        #enc_AES_key = self.get_aes_key(selected_file_name)

        # Decode, decrypt, merge into a local file
        #self.file_handler.downloadFile(file_chunks, bytearray(enc_AES_key), download_path)
        #maclist = []
        data = self.new_file_handler.downloader_helper(file_chunks, len(file_chunks))

        # Construct the file path
        file_path = os.path.join(download_path, selected_file_metadata['file_name'])

        with open(file_path, 'wb') as f:
            f.write(data)

        return

    def check_files(self):
        # Get file metadata from smart contract
        files_metadata = json.loads(self.connector.list_file())
        #files_metadata = self.connector.list_file()

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

            # # Remove nodes from server
            # # TODO: if failed, do sth
            # self.remove_chunks_from_server(node_ips_server)

            # Remove the file from the smart contract
            # receipt = await asyncio.wait_for(self.connector.remove_file(selected_file_metadata["root_hash"]), timeout=None)

            # Set up retry count
            retry_count = 0

            # Upload the metadata to the smart contract, retrying up to 3 times if necessary
            while retry_count < 3:
                # TODO: BYTES OR BYTES32?
                receipt = self.connector.remove_file(bytes(selected_file_metadata["root_hash"], "utf8"))

                if receipt['status'] == 1:
                    print("File metadata uploaded to blockchain successfully!")
                    break  # Exit the loop if successful
                else:
                    retry_count += 1
                    print("Error uploading file to blockchain. Retrying...")

            # Check if the upload was successful after retrying
            if receipt['status'] != 1:
                print("Failed to upload file metadata to blockchain after 3 attempts. Aborting upload.")

            return





if __name__ == '__main__':
    client = Client()
    client.run()
