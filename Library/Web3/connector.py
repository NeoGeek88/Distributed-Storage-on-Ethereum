from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from dotenv import load_dotenv
import os
import json
from ..Crypto import MerkleTree

class Connector:
    def __init__(self):
        # Load the environment variables from the .env file.
        # TODO: might not need .env in the future i guesss
        load_dotenv("./.env")

        # Connect to the Ethereum blockchain via remote node provider.
        self.w3 = Web3(Web3.HTTPProvider(os.getenv("INFURA_NODE_ENDPOINT")))

        # Load the contract ABI and contract address.
        with open('./Contract/contract_abi.json', 'r') as f: 
            contract_abi = json.load(f)
        
        contract_address = os.getenv("CONTRACT_ADDRESS")
        self.contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)


    def file_preprocess(self, file_json):
        '''
        Purpose: Pre-check the provided file details before making the transaction. 
        Input: File details including file name, file size, file root hash, file chunks info.
        Output: Argument list for calling corresponding smart contract function + Error message.
        '''
        file_details = json.loads(file_json)

        # =========== FILE PRE-PRECESSING ===========
        # File name should be provided and should not be empty string.
        if ("file_name" in file_details) and (file_details["file_name"] is not None):
            if file_details["file_name"]:
                file_name = file_details["file_name"] 
            else: 
                return {"args": None, "err": "FILE NAME SHOULD NOT BE EMPTY."}
        else:
            return {"args": None, "err": "MISSING FILE NAME INFORMATION."}

        # File size should be provided and should be integer (or should able to convert to integer).
        if ("file_size" in file_details) and (file_details["file_size"] is not None):
            if file_details["file_size"]:
                if isinstance(file_details["file_size"], int):
                    file_size = file_details["file_size"]
                else:
                    try:
                        file_size = int(file_details["file_size"])
                        if file_size < 0:
                            return {"args": None, "err": "FILE SIZE SHOULD NOT LESS THAN 0 BYTE."}
                    except ValueError:
                        return {"args": None, "err": "FILE SIZE SHOULD BE INTEGER."}
            else:
                return {"args": None, "err": "FILE SIZE SHOULD NOT BE EMPTY."}
        else:
            return {"args": None, "err": "MISSING FILE SIZE INFORMATION."} 

        # File root hash should be provided and should be 32-byte hex string. 
        if ("root_hash" in file_details) and (file_details["root_hash"] is not None):
            if file_details["root_hash"]:
                root_hash_raw = file_details["root_hash"]
                if not root_hash_raw.startswith("0x"):
                    root_hash_raw = "0x" + root_hash_raw
                if len(root_hash_raw) != 66:
                    return {"args": None, "err": "PROVIDED ROOT HASH STRING IS NOT 32-BYTE."}
                try:
                    root_hash_int = int(root_hash_raw, 16)
                    root_hash = hex(root_hash_int)
                except ValueError:
                    return {"args": None, "err": "CAN NOT CONVERT PROVIDED ROOT HASH STRING TO HEX."}
            else: 
                return {"args": None, "err": "FILE ROOT HASH SHOULD NOT BE EMPTY."}
        else:
            return {"args": None, "err": "MISSING FILE ROOT HASH."}  

        # File chunks list should be provided but can be empty.
        file_chunks = []
        if ("file_chunks" in file_details) and (file_details["file_chunks"] is not None):
            if isinstance(file_details["file_chunks"], list): 
                try:
                    file_chunks_raw = file_details["file_chunks"]
                    for chunk_obj in file_chunks_raw:
                        for k, v in chunk_obj.items():
                            file_chunks.append([k,v])
                except:
                    return {"args": None, "err": "ERROR WHEN PARSING THE FILE CHUNK DETAILS."}
            else: 
                return {"args": None, "err": "FILE CHUNKS SHOULD BE PROVIDED IN THE FORM OF A LIST."}
        else:
            return {"args": None, "err": "MISSING FILE CHUNKS INFORMATION."}

        args = [
            file_name,
            file_size,
            root_hash,
            file_chunks
        ]
        return {"args": args, "err": None}


    def node_preprocess(self, node_json):
        '''
        PURPOSE: Pre-check provided node details before making the transaction. 
        INPUT: Node details including node ID, net address, communication protocol, port info.
        RETURN: Argument list for calling corresponding smart contract function + .
        # TODO: return an object contains arguemnet list + error  
        {args: [], err: string}
        {args: '', err: }
        '''
        node_details = json.loads(node_json)

        # =========== NODE PRE-PRECESSING ===========
        # Node ID should be provided and should not be empty string.
        # TODO: check if node ID is a valid uuid!!!
        if ("node_id" in node_details) and (node_details["node_id"] is not None):
            if node_details["node_id"]:
                node_id = node_details["node_id"] 
            else: 
                return "message: node ID should not be empty."
        else:
            return "message: missing node ID info."
        
        # IP address should be provided and should not be empty string.
        if ("ip_address" in node_details) and (node_details["ip_address"] is not None):
            if node_details["ip_address"]:
                ip_address = node_details["ip_address"] 
            else: 
                return "message: IP address should not be empty."
        else:
            return "message: missing IP address info."
        
        # Net address should be provided, but it can be empty.
        if ("net_address" in node_details) and (node_details["net_address"] is not None):
            if node_details["net_address"]:
                net_address = node_details["net_address"] 
            else: 
                net_address = ""
        else:
            return "message: missing net address info."
        
        # Protocol must be one of 3 values, 0(TCP), 1(UDP) or 2(Others).
        if ("protocol" in node_details) and (node_details["protocol"] is not None):
            if node_details["protocol"] in range(3):
                protocol = node_details["protocol"] 
            else: 
                return "message: invalid protocol info (must be 0(TCP), 1(UDP) or 2(Others))."
        else:
            return "message: missing protocol info."

        # Port number should be provided and should be integer (or should able to convert to integer).
        # Port number must also less than 65535
        if ("port" in node_details) and (node_details["port"] is not None):
            if node_details["port"]:
                if isinstance(node_details["port"], int):
                    if port < 1 or port > 65535:
                        return "message: port number should not less than 1 and should not bigger than 65535."
                    else:
                        port = node_details["port"]
                else:
                    try:
                        port = int(node_details["port"])
                        if port < 1 or port > 65535:
                            return "message: port number should not less than 1 and should not bigger than 65535."
                    except ValueError:
                        return "message: port number should be intger."
            else:
                return "message: port number should not be empty."
        else:
            return "message: missing port number info."

        args = [
            node_id,
            ip_address,
            net_address,
            protocol,
            port
        ]
        return args


    def generate_receipt(self, raw_receipt):
        '''
        Purpose: Generate the developer-friendly receipt for better debugging process.
        Input: Raw transaction receipt return from chain. 
        Output: Receipt with most common used data. 
        '''
        gas_price = raw_receipt["effectiveGasPrice"] * 10**(-9) # Unit in Gwei
        transaction_fee = raw_receipt["effectiveGasPrice"] * raw_receipt["gasUsed"] * 10**(-18) # Unit in ETH

        receipt = {
            "status": raw_receipt["status"],
            "transaction_hash": raw_receipt["transactionHash"],
            "transaction_fees": transaction_fee,
            "gas_price:": gas_price,
            "gas_used": raw_receipt["gasUsed"],
        }
        return receipt


    def list_file(self):
        '''
        Input: None
        Output: The metadata of all files that current address owns.
        '''
        raw_list_file = self.contract.functions.listFiles().call({
            "from": os.getenv("WALLET_PUBLIC_KEY")
        })

        list_file = []
        for f in raw_list_file:
            file = {}
            file["owner"] = f[0]
            file["file_name"] = f[1]
            file["file_size"] = f[2]
            file["root_hash"] = f[3].hex()
            file["file_chunk_count"] = f[4]

            file["file_chunks"] = []
            for c in f[5]:
                chunk = {}
                chunk["chunk_hash"] = c[0].hex()
                chunk["node_id"] = c[1]
                file["file_chunks"].append(chunk)

            list_file.append(file)

        list_file_json = json.dumps(list_file)
        print(list_file_json) # TODO: DEL LATER
        return list_file_json


    def sign_transaction(self, func_name, func_args):
        '''
        Purpose: A generic function for signing a transaction (for write function).
        Input: Function name to be invoked and required function arguments.
        Output: Transaction receipt with information like transaction status. 
        '''
        # Define function name and required arguments.
        function_name = func_name
        function_args = func_args

        # Build transaction.
        nonce = self.w3.eth.get_transaction_count(os.getenv("WALLET_PUBLIC_KEY"))
        gas_price = self.w3.eth.gas_price

        tx = self.contract.functions[function_name](*function_args).build_transaction({
            'nonce': nonce,
            'gasPrice': gas_price,
            'from': os.getenv("WALLET_PUBLIC_KEY")
        })
        tx['gas'] = self.w3.eth.estimate_gas(tx)
        private_key = os.getenv("WALLET_PRIVATE_KEY")

        # Sign and send the transaction. 
        signed_function = self.w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_function.rawTransaction)
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        # Generate transaction receipt.
        receipt = self.generate_receipt(tx_receipt)
        return receipt
 

    def upload_file(self, file_json):  
        '''
        Input: File details including file name, file size, file root hash, file chunks info.
        Output: Transaction receipt with information such as transaction status, or error message string if any.
        '''
        process_status = self.file_preprocess(file_json)
        if process_status["args"] is not None: 
            receipt = self.sign_transaction("addFile", process_status["args"])
            print(receipt) # DELETE LATER
            return receipt
        else:
            return process_status["err"]
 

    def retrieve_file(self, root_hash):
        '''
        Input: File root hash.
        Return: Metadata for that file.
        '''
        # Check return value to see if file exist.
        raw_retrieved_file = self.contract.functions.getFile(root_hash).call({
            "from": os.getenv("WALLET_PUBLIC_KEY")
        })

        retrieved_file = {}
        retrieved_file["owner"] = raw_retrieved_file[0]
        retrieved_file["file_name"] = raw_retrieved_file[1]
        retrieved_file["file_size"] = raw_retrieved_file[2]
        retrieved_file["root_hash"] = raw_retrieved_file[3].hex()
        retrieved_file["file_chunk_count"] = raw_retrieved_file[4]

        retrieved_file["file_chunks"] = []
        for c in raw_retrieved_file[5]:
            chunk = {}
            chunk["chunk_hash"] = c[0].hex()
            chunk["node_id"] = c[1]
            retrieved_file["file_chunks"].append(chunk)
        
        retrieved_file_json = json.dumps(retrieved_file)
        return retrieved_file_json

    
    def update_file(self, file_update_json):
        '''
        Purpose: This function is not used to update the file content, but update the node Id where the file chunk stored.
        Input: Updated file details including origianl file root hash, new file name, and updated file chunks list (Chunk hash : Node Id).
        Output: Transaction receipt with information such as transaction status, or error message string if any.
        '''
        process_status = self.file_preprocess(file_update_json)
        if process_status["args"] is not None:

            # Raw structure: [file_name, file_size, root_hash, file_chunks[]].
            raw_args = process_status["args"]

            # Reconstruct argument list: [root_hash, file_name, file_chunks[]].
            args = [
                raw_args[2], 
                raw_args[0], 
                raw_args[3]
            ]

            receipt = self.sign_transaction("updateFile", args)
            print(receipt) # DELETE LATER
            return receipt
        else:
            return process_status["err"]


    def remove_file(self, root_hash):  
        '''
        INPUT: file root hash.
        RETURN: transaction receipt with status (upload succeed or error code & msg). 
        # TODO: consider transaction not included in the chain
        '''
        # TODO: implement check hash function and apply here (refer line 261)
        
        function_name = 'removeFile'
        function_args = root_hash
        nonce = self.w3.eth.get_transaction_count(os.getenv("WALLET_PUBLIC_KEY"))
        gas_price = self.w3.eth.gas_price
        tx = self.contract.functions[function_name](*function_args).build_transaction({
            'nonce': nonce,
            'gasPrice': gas_price,
            'from': os.getenv("WALLET_PUBLIC_KEY")
        })
        tx['gas'] = self.w3.eth.estimate_gas(tx)
        private_key = os.getenv("WALLET_PRIVATE_KEY")

        # Sign and send the transaction. 
        signed_function = self.w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_function.rawTransaction)
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        receipt = self.generate_receipt(tx_receipt)
        print(receipt)
        return receipt
    

    def list_nodes(self):
        '''
        RETURN: The information of all nodes
        '''
        raw_list_node = self.contract.functions.listNodes().call({
            "from": os.getenv("WALLET_PUBLIC_KEY")
        })

        list_node = []
        for n in raw_list_node:
            node = {}
            node["node_id"] = n[0]
            node["ip_address"] = n[1]
            node["net_address"] = n[2]
            node["protocol"] = n[3]
            node["port"] = n[4]
            node["owner"] = n[5]
            list_node.append(node)

        list_node_json = json.dumps(list_node)
        print(list_node_json) # del later
        return list_node_json

    def get_node(self, node_id):
        '''
        INPUT: node ID
        RETURN: Node information
        '''
        raw_node = self.contract.functions.getNode(node_id).call({
            "from": os.getenv("WALLET_PUBLIC_KEY")
        })

        node = {}
        node["node_id"] = raw_node[0]
        node["ip_address"] = raw_node[1]
        node["net_address"] = raw_node[2]
        node["protocol"] = raw_node[3]
        node["port"] = raw_node[4]
        node["owner"] = raw_node[5]

        node_json = json.dumps(node)
        print(node_json) # del later
        return node_json

    def add_node(self, node_json):  
        '''
        INPUT: Node details including node ID, IP address, net address, communication protocol, port info.
        RETURN: transaction receipt with status (upload succeed or error code & msg). 
        # TODO: consider transaction not included in the chain
        '''
        args = self.node_preprocess(node_json)

        function_name = 'addNode'
        function_args = args
        nonce = self.w3.eth.get_transaction_count(os.getenv("WALLET_PUBLIC_KEY"))
        gas_price = self.w3.eth.gas_price
        tx = self.contract.functions[function_name](*function_args).build_transaction({
            'nonce': nonce,
            'gasPrice': gas_price,
            'from': os.getenv("WALLET_PUBLIC_KEY")
        })
        tx['gas'] = self.w3.eth.estimate_gas(tx)
        private_key = os.getenv("WALLET_PRIVATE_KEY")

        # Sign and send the transaction. 
        signed_function = self.w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_function.rawTransaction)
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        receipt = self.generate_receipt(tx_receipt)
        print(receipt)
        return receipt
    
    def remove_node(self, node_id):  
        '''
        INPUT: node id.
        RETURN: transaction receipt with status (upload succeed or error code & msg). 
        # TODO: consider transaction not included in the chain
        '''
        # TODO: check node ID is a valid uuid

        function_name = 'removeNode'
        function_args = node_id
        nonce = self.w3.eth.get_transaction_count(os.getenv("WALLET_PUBLIC_KEY"))
        gas_price = self.w3.eth.gas_price
        tx = self.contract.functions[function_name](*function_args).build_transaction({
            'nonce': nonce,
            'gasPrice': gas_price,
            'from': os.getenv("WALLET_PUBLIC_KEY")
        })
        tx['gas'] = self.w3.eth.estimate_gas(tx)
        private_key = os.getenv("WALLET_PRIVATE_KEY")

        # Sign and send the transaction. 
        signed_function = self.w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_function.rawTransaction)
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        receipt = self.generate_receipt(tx_receipt)
        print(receipt)
        return receipt
    
    def merkle_proof(self, file_json, index, leaf_hash):
        '''
        INPUT: file details including file name, file size, file root hash, file chunks info,
               and chunk index and the leaf hash to be proofed
        RETURN: boolean value inform whether the proof provided matches the root hash or not. 
        '''
        file_info = self.file_preprocess(file_json)
        mt = MerkleTree(file_info["file_chunks"])
        proof = mt.build_proof(index, len(file_info["file_chunks"]))
        root_hash = file_info["root_hash"]
        args = [proof, root_hash, leaf_hash, index]

        raw_proof_result = self.contract.functions.getFile(args).call({
            "from": os.getenv("WALLET_PUBLIC_KEY")
        })
        
        proof_result = json.dumps(raw_proof_result)
        return proof_result




if __name__ == '__main__':
    conn = Connector()
    #conn.retrieve_file("0x7f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d63")

    #err = conn.upload_file('{"file_name": "s", "file_size": "12", "root_hash": "0x7f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d6c", "file_chunks": []}')
    #err = conn.file_preprocess('{"file_name": "s", "file_size": "12", "root_hash": "0x7f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d6c", "file_chunks": []}')
    err = conn.update_file('{"file_name": "test_update", "file_size": "10", "root_hash": "0x7f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d6c", "file_chunks": []}')

    print(err)
    #conn.list_file()
    # if file_details["file_name"]:
      #      else: return "message: file ane should not be empty!"
